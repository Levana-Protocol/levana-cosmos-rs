use anyhow::Context;
use base64::Engine;

#[derive(serde::Serialize)]
struct Request {
    jsonrpc: String,
    method: String,
    id: u64,
    params: Params,
}
#[derive(serde::Serialize)]
struct Params {
    path: String,
    data: String,
    prove: bool,
}

#[derive(serde::Deserialize)]
struct Response {
    // id: u64,
    // jsonrpc: String,
    result: Result,
}
#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
enum Result {
    Response { value: String },
}

pub(super) async fn make_jsonrpc_request<Req, Res>(
    client: &reqwest::Client,
    endpoint: &str,
    req: Req,
    path: impl Into<String>,
) -> anyhow::Result<Res>
where
    Req: prost::Message,
    Res: prost::Message + Default,
{
    let id = rand::random();

    let req = Request {
        jsonrpc: "2.0".to_owned(),
        method: "abci_query".to_owned(),
        id,
        params: Params {
            path: path.into(),
            data: hex::encode(&req.encode_to_vec()),
            prove: false,
        },
    };

    let raw_body: String = client
        .post(endpoint)
        .json(&req)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let res = serde_json::from_str::<Response>(&raw_body)
        .with_context(|| format!("Unable to parse JSON response: {raw_body}"))?;

    let value = base64::engine::general_purpose::STANDARD
        .decode(match &res.result {
            Result::Response { value } => value,
        })
        .context("Invalid base64 RPC response")?;
    Ok(Res::decode(value.as_slice())?)
}
