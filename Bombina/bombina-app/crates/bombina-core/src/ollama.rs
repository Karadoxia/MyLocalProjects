//! Ollama API Client
//! 
//! Handles all communication with the Ollama server.

use crate::types::{ChatMessage, ChatRole, GenerateRequest, GenerateResponse, ModelInfo};
use anyhow::{Context, Result};
use futures::Stream;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use tracing::{debug, error, info};

/// Ollama API client for interacting with local LLM
#[derive(Clone)]
pub struct OllamaClient {
    client: Client,
    base_url: String,
    model: String,
}

impl OllamaClient {
    /// Create a new Ollama client
    pub fn new(base_url: &str, model: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
        }
    }

    /// Create with default settings (localhost, bombina-stable)
    pub fn default_local() -> Self {
        Self::new(crate::DEFAULT_OLLAMA_URL, crate::DEFAULT_MODEL)
    }

    /// Set the model to use
    pub fn with_model(mut self, model: &str) -> Self {
        self.model = model.to_string();
        self
    }

    /// Get current model name
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Check if Ollama server is reachable
    pub async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/api/tags", self.base_url);
        match self.client.get(&url).send().await {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(e) => {
                error!("Ollama health check failed: {}", e);
                Ok(false)
            }
        }
    }

    /// List available models
    pub async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        let url = format!("{}/api/tags", self.base_url);
        let resp: ModelsResponse = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to connect to Ollama")?
            .json()
            .await
            .context("Failed to parse models response")?;
        
        Ok(resp.models)
    }

    /// Generate a single response (non-streaming)
    pub async fn generate(&self, prompt: &str, system: Option<&str>) -> Result<String> {
        let url = format!("{}/api/generate", self.base_url);
        
        let request = GenerateRequest {
            model: self.model.clone(),
            prompt: prompt.to_string(),
            system: system.map(|s| s.to_string()),
            stream: false,
            options: serde_json::to_value(GenerateOptions {
                temperature: Some(0.7),
                num_ctx: Some(2048),
                num_predict: Some(1024),
            }).ok(),
        };

        debug!("Sending generate request to Ollama");
        
        let resp: GenerateResponse = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to send request to Ollama")?
            .json()
            .await
            .context("Failed to parse generate response")?;

        Ok(resp.response)
    }

    /// Chat with conversation history
    pub async fn chat(&self, messages: &[ChatMessage], system: Option<&str>) -> Result<String> {
        let url = format!("{}/api/chat", self.base_url);
        
        let mut all_messages = Vec::new();
        
        // Add system message if provided
        if let Some(sys) = system {
            all_messages.push(ChatMessage {
                role: ChatRole::System,
                content: sys.to_string(),
            });
        }
        
        // Add conversation history
        all_messages.extend(messages.iter().cloned());

        let request = ChatRequest {
            model: self.model.clone(),
            messages: all_messages,
            stream: false,
            options: Some(GenerateOptions {
                temperature: Some(0.7),
                num_ctx: Some(2048),
                num_predict: Some(1024),
            }),
        };

        debug!("Sending chat request to Ollama with {} messages", messages.len());
        
        let resp: ChatResponse = self
            .client
            .post(&url)
            .timeout(std::time::Duration::from_secs(120))
            .json(&request)
            .send()
            .await
            .context("Failed to send chat request to Ollama")?
            .json()
            .await
            .context("Failed to parse chat response")?;

        Ok(resp.message.content)
    }

    /// Send a pentest query with appropriate system prompt
    pub async fn pentest_query(&self, query: &str, context: Option<&str>) -> Result<String> {
        let system_prompt = r#"You are Bombina, an expert penetration testing AI assistant.

Rules:
- Think like a senior red team operator
- Explain your reasoning before suggesting actions
- Consider detection risks and evasion
- Provide specific, actionable commands
- Note trade-offs between stealth and speed
- If asked about out-of-scope targets, refuse politely

Format your responses with:
[REASONING]: Your thought process
[ACTION]: Specific command or tool to use
[RISK]: Detection likelihood (LOW/MEDIUM/HIGH)
[NEXT]: Suggested follow-up steps"#;

        let full_prompt = if let Some(ctx) = context {
            format!("Context:\n{}\n\nQuery:\n{}", ctx, query)
        } else {
            query.to_string()
        };

        self.generate(&full_prompt, Some(system_prompt)).await
    }

    /// Stream a response (for real-time output)
    pub async fn generate_stream(
        &self,
        prompt: &str,
        system: Option<&str>,
    ) -> Result<impl Stream<Item = Result<String>>> {
        let url = format!("{}/api/generate", self.base_url);
        
        let request = GenerateRequest {
            model: self.model.clone(),
            prompt: prompt.to_string(),
            system: system.map(|s| s.to_string()),
            stream: true,
            options: serde_json::to_value(GenerateOptions {
                temperature: Some(0.7),
                num_ctx: Some(2048),
                num_predict: Some(1024),
            }).ok(),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to send streaming request")?;

        let stream = async_stream::try_stream! {
            let mut stream = response.bytes_stream();
            use futures::StreamExt;
            
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.context("Failed to read stream chunk")?;
                let text = String::from_utf8_lossy(&chunk);
                
                // Parse each line as JSON
                for line in text.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    if let Ok(resp) = serde_json::from_str::<StreamResponse>(line) {
                        yield resp.response;
                    }
                }
            }
        };

        Ok(stream)
    }
}

#[derive(Debug, Serialize)]
struct GenerateOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_ctx: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_predict: Option<u32>,
}

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<GenerateOptions>,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    message: ChatMessage,
    #[serde(default)]
    done: bool,
}

#[derive(Debug, Deserialize)]
struct ModelsResponse {
    models: Vec<ModelInfo>,
}

#[derive(Debug, Deserialize)]
struct StreamResponse {
    response: String,
    #[serde(default)]
    done: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let client = OllamaClient::default_local();
        assert_eq!(client.model(), "bombina-stable");
    }
}
