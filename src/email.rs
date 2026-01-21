use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use tracing::{error, info};

pub fn send_email_alert(subject: &str, body: &str) {
    let subject = subject.to_string();
    let body = body.to_string();

    // 使用 spawn_blocking 避免阻塞异步执行器
    tokio::task::spawn_blocking(move || {
        let email_user = "charlieyuxx@gmail.com";
        let email_pass = "sabw gnll hfuq yesl";
        let email_to = "charlieyuxx@gmail.com";

        let email = match Message::builder()
            .from(email_user.parse().unwrap())
            .to(email_to.parse().unwrap())
            .subject(subject)
            .body(body)
        {
            Ok(e) => e,
            Err(e) => {
                error!("Email build failed: {:?}", e);
                return;
            }
        };

        let creds = Credentials::new(email_user.to_string(), email_pass.to_string());
        let mailer = SmtpTransport::relay("smtp.gmail.com")
            .unwrap()
            .credentials(creds)
            .build();

        match mailer.send(&email) {
            Ok(_) => info!("Email sent successfully!"),
            Err(e) => error!("Could not send email: {:?}", e),
        }
    });
}