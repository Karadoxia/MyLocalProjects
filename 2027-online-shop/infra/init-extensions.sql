-- NEXUS V2 — PostgreSQL Extensions Init
-- Runs automatically on first container start
-- Enables pgvector for AI agent memory / semantic search (replaces Pinecone)

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;  -- Trigram search (fuzzy matching)
CREATE EXTENSION IF NOT EXISTS unaccent; -- Accent-insensitive search

-- Create additional databases for other services
-- (Zitadel, Umami, Listmonk each need their own DB)
SELECT 'pg_vector extension enabled — Pinecone replaced at zero cost' AS status;
