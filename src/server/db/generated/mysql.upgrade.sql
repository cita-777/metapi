ALTER TABLE `accounts` ADD COLUMN `oauth_provider` TEXT;
ALTER TABLE `accounts` ADD COLUMN `oauth_account_key` TEXT;
ALTER TABLE `accounts` ADD COLUMN `oauth_project_id` TEXT;
CREATE UNIQUE INDEX `sites_platform_url_unique` ON `sites` (`platform`(191), `url`(191));
CREATE INDEX `accounts_oauth_identity_idx` ON `accounts` (`oauth_provider`(191), `oauth_account_key`(191), `oauth_project_id`(191));
CREATE INDEX `accounts_oauth_provider_idx` ON `accounts` (`oauth_provider`(191));
