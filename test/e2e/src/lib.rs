#[cfg(test)]
mod tests {
    use std::{fs::{read_to_string, write, File}, path::{Path, PathBuf}, process::Command, time::Duration};

    use candid::{CandidType, Decode, Deserialize, Encode};
    use ic_agent::{export::Principal, Agent};
    use like_shell::{run_successful_command, temp_dir_from_template, Capture, TemporaryChild};
    // use dotenv::dotenv;
    use tempdir::TempDir;
    use tokio::{join, time::sleep};
    use toml_edit::{value, DocumentMut};
    use anyhow::Context;
    use serde_json::Value;
    
    struct Test {
        dir: TempDir,
        // cargo_manifest_dir: PathBuf,
        workspace_dir: PathBuf,
    }
    
    impl Test {
        pub async fn new(tmpl_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
            let cargo_manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
            let workspace_dir = cargo_manifest_dir.join("..").join("..");
            let dir = temp_dir_from_template(tmpl_dir)?;
    
            let res = Self {
                dir,
                // cargo_manifest_dir: cargo_manifest_dir.to_path_buf(),
                workspace_dir: workspace_dir,
            };
    
            Ok(res)
        }
    }
    
    // TODO: Should have more abstract DFXDir.
    struct OurDFX<'a> {
        pub base: &'a Test,
        test_canister_id: Principal,
        agent: Agent,
    }
    
    impl<'a> OurDFX<'a> {
        pub async fn new(base: &'a Test, additional_args: &[&str]) -> Result<Self, Box<dyn std::error::Error>> {
            // TODO: Specifying a specific port is a hack.
            run_successful_command(&mut Command::new(
                "/root/.local/share/dfx/bin/dfx"
            ).args([&["start", "--host", "127.0.0.1:8007", "--background", "--clean"] as &[&str], additional_args].concat())
                .current_dir(base.dir.path().join("motoko")))
                .context("Starting DFX")?;
    
            let port_str = read_to_string(
                base.dir.path().join("motoko").join(".dfx").join("network").join("local").join("webserver-port"),
            ).context("Reading port.")?;
            let port: u16 = port_str.parse().context("Parsing port number.")?;
    
            run_successful_command(Command::new(
                "/root/.local/share/dfx/bin/dfx"
            ).args(["deploy"]).current_dir(base.dir.path().join("motoko")))?;
    
            let canister_ids: Value = {
                let dir = base.dir.path().join("motoko").join(".dfx").join("local").join("canister_ids.json");
                let file = File::open(dir).with_context(|| format!("Opening canister_ids.json"))?;
                serde_json::from_reader(file).expect("Error parsing JSON")
            };
            let test_canister_id = canister_ids.as_object().unwrap()["test"].as_object().unwrap()["local"].as_str().unwrap();
            let call_canister_id = canister_ids.as_object().unwrap()["call"].as_object().unwrap()["local"].as_str().unwrap();
    
            let agent = Agent::builder().with_url(format!("http://127.0.0.1:{port}")).build().context("Creating Agent")?;
            agent.fetch_root_key().await.context("Fetching root keys.")?; // DON'T USE this on mainnet
    
            let toml_path = base.dir.path().join("config.toml");
            let toml = read_to_string(&toml_path).context("Reading config.")?;
            let mut doc = toml.parse::<DocumentMut>().context("Invalid TOML")?;
            doc["callback"]["canister"] = value(call_canister_id.to_string());
            write(&toml_path, doc.to_string()).context("Writing modified config.")?;
    
            Ok(Self {
                base: &base,
                test_canister_id: Principal::from_text(test_canister_id)
                    .context("Parsing principal")?,
                agent,
            })
        }
    }
    
    impl<'a> Drop for OurDFX<'a> {
        fn drop(&mut self) {
            run_successful_command(&mut Command::new(
                "/root/.local/share/dfx/bin/dfx"
            ).args(["stop"]).current_dir(self.base.dir.path().join("motoko")))
                .context("Stopping DFX").expect("can't stop DFX");
        }
    }
    
    #[derive(Debug, Deserialize, CandidType)]
    struct HttpHeader {
        name: String,
        value: String,
    }
    
    async fn test_calls<'a>(test: &'a OurDFX<'a>, path: &str, arg: &str, body: &str) -> Result<Vec<HttpHeader>, Box<dyn std::error::Error>> {
        let res =
            test.agent.update(&test.test_canister_id, "test").with_arg(Encode!(&path, &arg, &body, &":8443", &":8081")?)
                .call_and_wait().await.context("Call to IC.")?;
        let (text, headers) = Decode!(&res, String, Vec<HttpHeader>).context("Decoding test call response.")?;
        assert_eq!(
            text,
            format!("path={}&arg={}&body={}", path, arg, body),
        );
        Ok(headers)
    }
    
    struct MyTest {
        pub test: Test,
        pub _test_http: TemporaryChild,
    }
    
    impl MyTest {
        pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let cargo_manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
            let tmpl_dir = cargo_manifest_dir.join("tmpl");
        
            let test = Test::new(&tmpl_dir).await?;
            let _test_http = TemporaryChild::spawn(&mut Command::new(
                test.workspace_dir.join("target").join("debug").join("test-server")
            ), Capture { stdout: None, stderr: None }).context("Running test HTTPS server")?;
            sleep(Duration::from_millis(1000)).await; // Wait till daemons start.
        
            Ok(MyTest {
                test,
                _test_http,
            })
        }
    }

    #[tokio::test]
    async fn test_artificial_delay() -> Result<(), Box<dyn std::error::Error>> {
        {
            let mytest = MyTest::new().await?;
            let dfx = OurDFX::new(&mytest.test, &["--artificial-delay", "0"]).await?;
            let _proxy = TemporaryChild::spawn(&mut Command::new(
                mytest.test.workspace_dir.join("target").join("debug").join("join-proxy")
            ).args(["-c", "config.toml"]).current_dir(mytest.test.dir.path()), Capture { stdout: None, stderr: None }).context("Running Joining Proxy")?;
            run_successful_command(Command::new(
                "/root/.local/share/dfx/bin/dfx"
            ).args(["deploy"]).current_dir(mytest.test.dir.path().join("motoko")))?;
            test_calls(&dfx, "/qq", "zz", "yu").await?;
            drop(dfx);
            drop(mytest);
        }
        {
            let mytest = MyTest::new().await?;
            let dfx = OurDFX::new(&mytest.test, &["--artificial-delay", "5000"]).await?;
            let _proxy = TemporaryChild::spawn(&mut Command::new(
                mytest.test.workspace_dir.join("target").join("debug").join("join-proxy")
            ).args(["-c", "config.toml"]).current_dir(mytest.test.dir.path()), Capture { stdout: None, stderr: None }).context("Running Joining Proxy")?;
            run_successful_command(Command::new(
                "/root/.local/share/dfx/bin/dfx"
            ).args(["deploy"]).current_dir(mytest.test.dir.path().join("motoko")))?;
            test_calls(&dfx, "/qq", "zz", "yu").await?;
            drop(dfx);
            drop(mytest);
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_loading_new() -> Result<(), Box<dyn std::error::Error>> {
        let mytest = MyTest::new().await?;
        let dfx = OurDFX::new(&mytest.test, &["--artificial-delay", "0"]).await?; // --artificial-delay just to speed up tests
        let _proxy = TemporaryChild::spawn(&mut Command::new(
            mytest.test.workspace_dir.join("target").join("debug").join("join-proxy")
        ).args(["-c", "config.toml"]).current_dir(mytest.test.dir.path()), Capture { stdout: None, stderr: None }).context("Running Joining Proxy")?;
        run_successful_command(Command::new(
            "/root/.local/share/dfx/bin/dfx"
        ).args(["deploy"]).current_dir(mytest.test.dir.path().join("motoko")))?;

        // Test that varying every one of three step parameters causes Miss:
        test_calls(&dfx, "/a", "b", "c").await?;
        test_calls(&dfx, "/ax", "b", "c").await?;
        test_calls(&dfx, "/ax", "bx", "c").await?;
        test_calls(&dfx, "/ax", "bx", "cx").await?;

        let (headers1, headers2, headers3) = join!(
            test_calls(&dfx, "/same", "x", "y"),
            test_calls(&dfx, "/same", "x", "y"),
            test_calls(&dfx, "/same", "x", "y"),
        );
        let headers1 = headers1?;
        let headers2 = headers2?;
        let headers3 = headers3?;

        let (mut hit_count, mut miss_count) = (0, 0);
        for headers in [&headers1, &headers2, &headers3] {
            if headers.iter().any(|h| h.name == "x-joinproxy-response" && h.value == "Hit") {
                hit_count += 1;
            }
            if headers.iter().any(|h| h.name == "x-joinproxy-response" && h.value == "Miss") {
                miss_count += 1;
            }
        }
        assert_eq!(miss_count, 1, "miss count");
        assert_eq!(hit_count, 2, "hit count");

        drop(dfx);
        drop(mytest);

        Ok(())
    }

    #[tokio::test]
    async fn test_port_443() -> Result<(), Box<dyn std::error::Error>> {
        let mytest = MyTest::new().await?;
        let dfx = OurDFX::new(&mytest.test, &["--artificial-delay", "0"]).await?; // --artificial-delay just to speed up tests
        let _proxy = TemporaryChild::spawn(&mut Command::new(
            mytest.test.workspace_dir.join("target").join("debug").join("join-proxy")
        ).args(["-c", "config.toml"]).current_dir(mytest.test.dir.path()), Capture { stdout: None, stderr: None }).context("Running Joining Proxy")?;
        run_successful_command(Command::new(
            "/root/.local/share/dfx/bin/dfx"
        ).args(["deploy"]).current_dir(mytest.test.dir.path().join("motoko")))?;
        let _test_http2 = TemporaryChild::spawn(&mut Command::new(
            mytest.test.workspace_dir.join("target").join("debug").join("test-server")
        ).args(["-p", "443"]), Capture { stdout: None, stderr: None }).context("Running mytest.test HTTPS server")?;
        sleep(Duration::from_millis(1000)).await; // Wait till daemons start.

        // Check https://local.vporton.name vs https://local.vporton.name:443
        let res =
            dfx.agent.update(&dfx.test_canister_id, "test").with_arg(Encode!(&"/headers", &"", &"", &"", &"")?)
                .call_and_wait().await.context("Call to IC 2.")?;
        let (text, _headers) = Decode!(&res, String, Vec<HttpHeader>).context("Decoding test call response.")?;
        assert!(
            text.contains("host: local.vporton.name\n"),
        );
            // local.vporton.name:443
        let res =
            dfx.agent.update(&dfx.test_canister_id, "test").with_arg(Encode!(&"/headers", &"", &"", &":443", &":443")?)
                .call_and_wait().await.context("Call to IC 2.")?;
        let (text, _headers) = Decode!(&res, String, Vec<HttpHeader>).context("Decoding test call response.")?;
        assert!(
            text.contains("host: local.vporton.name:443\n"),
        );
        drop(dfx);
        drop(mytest);

        Ok(())
    }
}