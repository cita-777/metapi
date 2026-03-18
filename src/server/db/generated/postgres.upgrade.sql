ALTER TABLE "accounts" ADD COLUMN "oauth_provider" TEXT;
ALTER TABLE "accounts" ADD COLUMN "oauth_account_key" TEXT;
ALTER TABLE "accounts" ADD COLUMN "oauth_project_id" TEXT;
CREATE UNIQUE INDEX "sites_platform_url_unique" ON "sites" ("platform", "url");
CREATE INDEX "accounts_oauth_identity_idx" ON "accounts" ("oauth_provider", "oauth_account_key", "oauth_project_id");
CREATE INDEX "accounts_oauth_provider_idx" ON "accounts" ("oauth_provider");
