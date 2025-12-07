import { ethers } from "ethers";

// ================= 1. 终极配置 (Configuration) =================
const CONFIG = {
    // [网络]
    WS_RPC_URL: "ws://your-private-node:8546", 
    HTTP_RPC_URL: "https://mainnet.base.org", 
    PRIVATE_KEY: "YOUR_PRIVATE_KEY", 

    // [Base Mainnet Addresses]
    FACTORY_ADDR: "0x33128a8fC17869897dcE68Ed026d694621f6FDfD", 
    ROUTER_ADDR: "0x262666956Ac873300a64570631270605a6E57Eaa",
    QUOTER_ADDR: "0x3d4e44Eb1374240CE6F1484383A1E93e212287a5", 
    WETH_ADDR: "0x4200000000000000000000000000000000000006",

    // [资金管理]
    SNIPE_AMOUNT_ETH: "0.05", // 每次冲 0.05 ETH

    // [你的核心策略]
    TAKE_PROFIT: 1.5,        // 1.5倍 止盈
    TRAILING_STOP_LOSS: 0.9, // 10% 回撤 止损
    
    // [安全参数]
    MAX_LIQUIDITY_WAIT: 60,  // 最多等 60秒流动性，超时放弃
    GAS_MULTIPLIER: 1.5,     // 加速倍数
    WATCHDOG_TIMEOUT: 10000, // 节点假死判定时间
};

// ================= 2. ABI =================
const FACTORY_ABI = ["event PoolCreated(address indexed token0, address indexed token1, uint24 indexed fee, int24 tickSpacing, address pool)"];
const ERC20_ABI = [
    "function approve(address spender, uint256 amount) external returns (bool)",
    "function allowance(address owner, address spender) external view returns (uint256)",
    "function balanceOf(address account) external view returns (uint256)",
    "function symbol() external view returns (string)",
    "function name() external view returns (string)"
];
const ROUTER_ABI = ["function exactInputSingle(tuple(address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96) params) external payable returns (uint256 amountOut)"];
const QUOTER_ABI = ["function quoteExactInputSingle(tuple(address tokenIn, address tokenOut, uint24 fee, uint256 amountIn, uint160 sqrtPriceLimitX96) params) external returns (uint256 amountOut)"];

// ================= 3. 全局变量 =================
let activeProvider: ethers.Provider;
let activeWallet: ethers.Wallet;
let factoryContract: ethers.Contract;
let routerContract: ethers.Contract;
let quoterContract: ethers.Contract;

let isSnipping = false; // 全局锁

// ================= 4. 安全模块 (Safety Module) =================

// [安全检查 1] 等待流动性注入 (Anti-No-Liquidity)
async function waitForLiquidity(token: string, fee: number): Promise<boolean> {
    console.log(`[Safety] 正在检测流动性...`);
    const startTime = Date.now();
    
    while (Date.now() - startTime < CONFIG.MAX_LIQUIDITY_WAIT * 1000) {
        try {
            // 尝试询价：用 0.01 ETH 试探
            const params = {
                tokenIn: CONFIG.WETH_ADDR,
                tokenOut: token,
                fee: fee,
                amountIn: ethers.parseEther("0.01"),
                sqrtPriceLimitX96: 0
            };
            // 如果 staticCall 成功且返回 > 0，说明池子有钱了
            const res = await quoterContract.getFunction("quoteExactInputSingle").staticCall(params);
            if (res[0] > 0n) {
                console.log(`[Safety] 流动性已添加! 此时可买.`);
                return true;
            }
        } catch (e) {
            // 报错说明池子还是空的，继续等
            process.stdout.write("."); 
        }
        await new Promise(r => setTimeout(r, 1000)); // 每秒查一次
    }
    console.log(`\n[Safety] 超时! ${CONFIG.MAX_LIQUIDITY_WAIT}秒内无流动性，放弃.`);
    return false;
}

// [安全检查 2] 简单的貔貅/蜜罐检测 (Anti-Honeypot Simulation)
async function checkHoneypot(token: string, fee: number): Promise<boolean> {
    console.log(`[Safety] 🐝 正在模拟买卖 (防貔貅检查)...`);
    try {
        // 1. 模拟买入
        const buyParams = {
            tokenIn: CONFIG.WETH_ADDR,
            tokenOut: token,
            fee: fee,
            amountIn: ethers.parseEther("0.01"),
            sqrtPriceLimitX96: 0
        };
        const buyOut = await quoterContract.getFunction("quoteExactInputSingle").staticCall(buyParams);

        // 2. 模拟卖出 (关键! 很多貔貅这里会报错)
        const sellParams = {
            tokenIn: token,
            tokenOut: CONFIG.WETH_ADDR,
            fee: fee,
            amountIn: buyOut[0], // 尝试卖出刚才模拟买到的量
            sqrtPriceLimitX96: 0
        };
        await quoterContract.getFunction("quoteExactInputSingle").staticCall(sellParams);
        
        console.log(`[Safety] 模拟交易通过. 看起来安全.`);
        return true;
    } catch (e) {
        console.warn(`[Safety] 模拟卖出失败! 可能是貔貅 (Honeypot) 或高税盘. 跳过.`);
        return false;
    }
}

// ================= 5. 核心动作 =================

// 获取加速 Gas
async function getBoostedGas() {
    const feeData = await activeProvider.getFeeData();
    const marketMax = feeData.maxFeePerGas ?? ethers.parseUnits("3", "gwei");
    const marketPriority = feeData.maxPriorityFeePerGas ?? ethers.parseUnits("0.1", "gwei");
    const boost = BigInt(Math.floor(CONFIG.GAS_MULTIPLIER * 100));
    return {
        maxFeePerGas: (marketMax * boost) / 100n,
        maxPriorityFeePerGas: (marketPriority * boost) / 100n
    };
}

// 卖出 (你的策略终点)
async function sell(token: string, fee: number, amount: bigint) {
    console.log(`[Sell] 执行卖出!`);
    try {
        if (routerContract.runner !== activeWallet) routerContract = routerContract.connect(activeWallet) as ethers.Contract;
        const gas = await getBoostedGas();

        const tx = await routerContract.exactInputSingle({
            tokenIn: token,
            tokenOut: CONFIG.WETH_ADDR,
            fee: fee,
            recipient: activeWallet.address,
            deadline: Math.floor(Date.now()/1000) + 120,
            amountIn: amount,
            amountOutMinimum: 0, 
            sqrtPriceLimitX96: 0
        }, { maxFeePerGas: gas.maxFeePerGas, maxPriorityFeePerGas: gas.maxPriorityFeePerGas, gasLimit: 350000n });

        console.log(`[Sell] Tx: ${tx.hash}`);
        await tx.wait();
        console.log(`[Sell] 成功逃顶. 任务结束.`);
        process.exit(0);
    } catch (e) { console.error(`[Sell] Fail:`, e); }
}

// 监控 (你的策略核心)
async function startMonitorLoop(token: string, fee: number, balance: bigint, initialInv: bigint) {
    console.log(`[Monitor] 启动策略监控 (TP: ${CONFIG.TAKE_PROFIT}x, SL: ${CONFIG.TRAILING_STOP_LOSS}x)`);
    
    // 状态
    const context = { highestValue: initialInv, isSold: false };
    
    // 定义核心检查函数 (被 WS 和 HTTP 共同调用)
    const checkLogic = async (source: string) => {
        if (context.isSold) return;
        try {
            if (quoterContract.runner !== activeProvider) quoterContract = quoterContract.connect(activeProvider) as ethers.Contract;
            
            // 询价
            const val = (await quoterContract.getFunction("quoteExactInputSingle").staticCall({
                tokenIn: token, tokenOut: CONFIG.WETH_ADDR, fee: fee, amountIn: balance, sqrtPriceLimitX96: 0
            }))[0];

            // 策略更新
            if (val > context.highestValue) context.highestValue = val;
            
            const stopLoss = (context.highestValue * BigInt(Math.floor(CONFIG.TRAILING_STOP_LOSS * 100))) / 100n;
            const takeProfit = (initialInv * BigInt(Math.floor(CONFIG.TAKE_PROFIT * 100))) / 100n;
            const roi = Number(val * 10000n / initialInv) / 100;

            process.stdout.write(`\r[${source}] Val: ${ethers.formatEther(val).slice(0,6)} | ROI: ${roi}% | High: ${ethers.formatEther(context.highestValue).slice(0,6)}`);

            // 触发
            if (val >= takeProfit) {
                console.log(`\n[Trigger] 止盈!`);
                context.isSold = true;
                await sell(token, fee, balance);
            } else if (val <= stopLoss) {
                console.log(`\n[Trigger] 📉 移动止损!`);
                context.isSold = true;
                await sell(token, fee, balance);
            }
        } catch (e) {}
    };

    // 启动 HTTP 轮询作为保底
    setInterval(() => checkLogic("HTTP"), 2000);

    // 绑定 WS 监听作为主力
    const wsProvider = activeProvider as ethers.WebSocketProvider;
    if (wsProvider.on) {
        wsProvider.on("block", () => checkLogic("WS"));
    }
}

// 执行完整的狙击流程
async function executeSnipe(targetToken: string, feeTier: number) {
    if (isSnipping) return;
    isSnipping = true;

    console.log(`\n[Sniper] 发现目标: ${targetToken}`);

    // 0. 打印代币信息 (防同名假币 - 人眼识别)
    try {
        const tokenCtx = new ethers.Contract(targetToken, ERC20_ABI, activeProvider);
        const name = await tokenCtx.name();
        const symbol = await tokenCtx.symbol();
        console.log(`[Info] Token: ${name} (${symbol})`);
    } catch (e) { console.log(`[Info] 无法获取代币名称.`); }

    // 1. 安全检查: 等待流动性 (防止买入失败)
    const hasLiquidity = await waitForLiquidity(targetToken, feeTier);
    if (!hasLiquidity) { isSnipping = false; return; }

    // 2. 安全检查: 模拟 (防止貔貅)
    const isSafe = await checkHoneypot(targetToken, feeTier);
    if (!isSafe) { isSnipping = false; return; }

    // 3. 真正买入
    try {
        console.log(`[Sniper] 执行买入...`);
        const amountIn = ethers.parseEther(CONFIG.SNIPE_AMOUNT_ETH);
        const gas = await getBoostedGas();
        
        // 检查 WETH 授权
        const wethCtx = new ethers.Contract(CONFIG.WETH_ADDR, ERC20_ABI, activeWallet);
        if ((await wethCtx.allowance(activeWallet.address, CONFIG.ROUTER_ADDR)) < amountIn) {
            await (await wethCtx.approve(CONFIG.ROUTER_ADDR, ethers.MaxUint256)).wait();
        }

        const tx = await routerContract.exactInputSingle({
            tokenIn: CONFIG.WETH_ADDR,
            tokenOut: targetToken,
            fee: feeTier,
            recipient: activeWallet.address,
            deadline: Math.floor(Date.now()/1000) + 120,
            amountIn: amountIn,
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        }, { maxFeePerGas: gas.maxFeePerGas, maxPriorityFeePerGas: gas.maxPriorityFeePerGas, gasLimit: 400000n });
        
        await tx.wait();
        
        // 4. 确认余额
        const tokenCtx = new ethers.Contract(targetToken, ERC20_ABI, activeProvider);
        const balance = await tokenCtx.balanceOf(activeWallet.address);
        console.log(`[Sniper] 买入成功! 余额: ${balance}`);

        if (balance === 0n) throw new Error("买入数量为0");

        // 5. 立即授权 (为快速卖出做准备)
        console.log(`[Sniper] 立即授权卖出...`);
        await (await tokenCtx.approve(CONFIG.ROUTER_ADDR, ethers.MaxUint256)).wait();

        // 6. 进入监控
        await startMonitorLoop(targetToken, feeTier, balance, amountIn);

    } catch (e) {
        console.error(`[Sniper] 流程中断: ${(e as Error).message}`);
        isSnipping = false; // 出错重置
    }
}

// ================= 6. 监听入口 =================
async function startListener() {
    console.log(`[System] 📡 启动全自动扫描...`);
    
    // 初始化
    activeProvider = new ethers.WebSocketProvider(CONFIG.WS_RPC_URL);
    activeWallet = new ethers.Wallet(CONFIG.PRIVATE_KEY, activeProvider);
    factoryContract = new ethers.Contract(CONFIG.FACTORY_ADDR, FACTORY_ABI, activeProvider);
    routerContract = new ethers.Contract(CONFIG.ROUTER_ADDR, ROUTER_ABI, activeWallet);
    quoterContract = new ethers.Contract(CONFIG.QUOTER_ADDR, QUOTER_ABI, activeProvider);

    // 监听工厂事件
    factoryContract.on("PoolCreated", async (token0, token1, fee, tickSpacing, pool) => {
        if (isSnipping) return;

        // 筛选 WETH 对子
        let target = "";
        if (token0.toLowerCase() === CONFIG.WETH_ADDR.toLowerCase()) target = token1;
        else if (token1.toLowerCase() === CONFIG.WETH_ADDR.toLowerCase()) target = token0;
        else return; // 忽略非 WETH 池子

        // 启动流程
        await executeSnipe(target, fee);
    });

    // 防止 WS 断连
    (activeProvider as any)._websocket.on("close", () => {
        console.log("WS 断开，重启中...");
        startListener();
    });
}

// 启动
startListener();