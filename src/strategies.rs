#![allow(dead_code)]
#![allow(deprecated)]

use crate::constants::*;
use crate::decoder::PoolKey;
use anyhow::Result;
use ethers::prelude::*;
use std::sync::Arc;

pub mod v2;
pub mod v3;
pub mod v4;
pub mod aerodrome;
pub mod virtuals;

pub use v2::UniswapV2Strategy;
pub use v3::UniswapV3Strategy;
pub use v4::UniswapV4Strategy;
pub use aerodrome::AerodromeV2Strategy;
pub use virtuals::VirtualsStrategy;

/// 定义模拟器的行为模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulationBehavior {
    Standard,  // 标准模式：Quote -> Buy -> Check Balance -> Sell
    QuoteOnly, // 仅报价模式：只要 Quote 成功即视为通过 (用于 V4 等复杂协议)
}

/// 定义所有 DEX 协议必须遵循的标准接口
pub trait DexStrategy: Send + Sync {
    fn name(&self) -> &str;

    /// 返回 (目标合约地址, 调用数据, 发送的 ETH 金额) 用于获取报价 (支持 token_in -> token_out)
    fn encode_quote(
        &self,
        amount_in: U256,
        token_in: Address,
        token_out: Address,
    ) -> Result<(Address, Bytes, U256)>;

    /// 解码报价返回的原始字节，得到预期的 Token 数量
    fn decode_quote(&self, output: Bytes) -> Result<U256>;

    /// 返回 (目标合约地址, 调用数据, 发送的 ETH 金额) 用于执行买入
    fn encode_buy(
        &self,
        amount_in: U256,
        token_out: Address,
        recipient: Address,
        deadline: U256,
        amount_out_min: U256,
    ) -> Result<(Address, Bytes, U256)>;

    /// 返回 (目标合约地址, 调用数据, 发送的 ETH 金额) 用于执行卖出
    fn encode_sell(
        &self,
        amount_in: U256,
        token_out: Address,
        recipient: Address,
        deadline: U256,
        amount_out_min: U256,
    ) -> Result<(Address, Bytes, U256)>;

    /// 报价是否需要 commit 状态（大多数是 View，但有些如 Virtuals 需要模拟执行）
    fn quote_requires_commit(&self) -> bool {
        false
    }

    /// 获取该策略在模拟器中的行为模式
    fn simulation_behavior(&self) -> SimulationBehavior {
        SimulationBehavior::Standard
    }

    // 用于持久化存储的元数据
    fn fee(&self) -> u32 {
        0
    }
    fn pool_key(&self) -> Option<PoolKey> {
        None
    }
}

/// 根据持久化的 PositionData 恢复策略对象
pub fn get_strategy_for_position(
    router: Address,
    fee: u32,
    token: Address,
) -> Box<dyn DexStrategy> {
    if router == *UNIV3_ROUTER || router == *PANCAKESWAP_V3_ROUTER || router == *AERO_V3_ROUTER {
        let quoter = if router == *PANCAKESWAP_V3_ROUTER {
            *PANCAKESWAP_V3_QUOTER
        } else if router == *AERO_V3_ROUTER {
            *AERO_V3_QUOTER
        } else {
            *UNIV3_QUOTER
        };
        Box::new(UniswapV3Strategy {
            router,
            quoter,
            fee,
            name: format!("Restored V3 ({})", fee),
        })
    } else if router == *VIRTUALS_FACTORY_ROUTER {
        Box::new(VirtualsStrategy {
            name: "Restored Virtuals".into(),
        })
    } else if router == *VIRTUALS_ROUTER {
        Box::new(AerodromeV2Strategy {
            router: *AERODROME_ROUTER,
            factory: *AERODROME_FACTORY,
            path: vec![*WETH_BASE, *VIRTUALS_ROUTER, token],
            name: "Restored Virtuals Hop".into(),
        })
    } else if router == *AERODROME_ROUTER {
        Box::new(AerodromeV2Strategy {
            router,
            factory: *AERODROME_FACTORY,
            path: vec![token, *WETH_BASE],
            name: "Restored Aero V2".into(),
        })
    } else {
        Box::new(UniswapV2Strategy {
            router,
            name: "Restored V2".into(),
        })
    }
}

/// 获取所有用于扫描的策略列表
pub fn get_all_strategies(
    token_addr: Address,
    v4_pool_key: Option<PoolKey>,
) -> Vec<Arc<dyn DexStrategy>> {
    let mut strategies: Vec<Arc<dyn DexStrategy>> = Vec::new();

    // 1. Uniswap V4 (如果提取到了 PoolKey)
    if let Some(pk) = v4_pool_key {
        strategies.push(Arc::new(UniswapV4Strategy {
            pool_key: pk,
            name: "Extracted V4 Key".into(),
        }));
    }

    // 1.1 [新增] Clanker V4 盲测策略 (针对 Clanker V4.1)
    // 排序：Uniswap V4 要求 currency0 < currency1
    let (c0, c1) = if token_addr < *WETH_BASE {
        (token_addr, *WETH_BASE)
    } else {
        (*WETH_BASE, token_addr)
    };

    // 构造 Clanker V4.1 常见的两种池子配置
    // 配置 A: 1% 固定费率 (10000), TickSpacing 200, Static Hook
    strategies.push(Arc::new(UniswapV4Strategy {
        pool_key: (c0, c1, 10000, 200, *CLANKER_HOOK_STATIC),
        name: "Clanker V4 Static (Guess)".into(),
    }));

    // 配置 B: 动态费率 (Flag 0x800000), TickSpacing 200, Dynamic Hook
    strategies.push(Arc::new(UniswapV4Strategy {
        pool_key: (c0, c1, 0x800000, 200, *CLANKER_HOOK_DYNAMIC),
        name: "Clanker V4 Dynamic (Guess)".into(),
    }));

    // 配置 C: 针对部分老池子或特殊配置的盲测 (1% Fee, TickSpacing 60)
    strategies.push(Arc::new(UniswapV4Strategy {
        pool_key: (c0, c1, 10000, 60, *CLANKER_HOOK_STATIC),
        name: "Clanker V4 Static 60ts (Guess)".into(),
    }));

    // 2. Uniswap V3 & Forks (Aerodrome Slipstream, PancakeSwap V3)
    strategies.push(Arc::new(UniswapV3Strategy {
        router: *UNIV3_ROUTER,
        quoter: *UNIV3_QUOTER,
        fee: 10000,
        name: "UniV3 1%".into(),
    }));
    strategies.push(Arc::new(UniswapV3Strategy {
        router: *UNIV3_ROUTER,
        quoter: *UNIV3_QUOTER,
        fee: 3000,
        name: "UniV3 0.3%".into(),
    }));
    strategies.push(Arc::new(UniswapV3Strategy {
        router: *UNIV3_ROUTER,
        quoter: *UNIV3_QUOTER,
        fee: 500,
        name: "UniV3 0.05%".into(),
    }));
    strategies.push(Arc::new(UniswapV3Strategy {
        router: *PANCAKESWAP_V3_ROUTER,
        quoter: *PANCAKESWAP_V3_QUOTER,
        fee: 2500,
        name: "Pancake V3".into(),
    }));
    strategies.push(Arc::new(UniswapV3Strategy {
        router: *AERO_V3_ROUTER,
        quoter: *AERO_V3_QUOTER,
        fee: 100,
        name: "Aero V3 (Slipstream)".into(),
    }));

    // 3. Uniswap V2 Forks
    strategies.push(Arc::new(UniswapV2Strategy {
        router: *SUSHI_ROUTER,
        name: "Sushi V2".into(),
    }));
    strategies.push(Arc::new(UniswapV2Strategy {
        router: *BASESWAP_ROUTER,
        name: "BaseSwap V2".into(),
    }));
    strategies.push(Arc::new(UniswapV2Strategy {
        router: *ALIENBASE_ROUTER,
        name: "AlienBase V2".into(),
    }));
    strategies.push(Arc::new(UniswapV2Strategy {
        router: *SWAPBASED_ROUTER,
        name: "SwapBased V2".into(),
    }));
    strategies.push(Arc::new(UniswapV2Strategy {
        router: *ROCKETSWAP_ROUTER,
        name: "RocketSwap V2".into(),
    }));

    // 4. Aerodrome V2 & Virtuals
    strategies.push(Arc::new(AerodromeV2Strategy {
        router: *AERODROME_ROUTER,
        factory: *AERODROME_FACTORY,
        path: vec![*WETH_BASE, token_addr],
        name: "Aero V2 Direct".into(),
    }));
    strategies.push(Arc::new(VirtualsStrategy {
        name: "Virtuals Factory".into(),
    }));

    strategies
}
