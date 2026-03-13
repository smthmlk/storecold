#[tokio::main]
async fn main() -> anyhow::Result<()> {
    storecold::run().await
}
