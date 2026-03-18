ALTER TABLE `accounts` ADD `oauth_provider` text;
--> statement-breakpoint
ALTER TABLE `accounts` ADD `oauth_account_key` text;
--> statement-breakpoint
ALTER TABLE `accounts` ADD `oauth_project_id` text;
--> statement-breakpoint
UPDATE `accounts`
SET
  `oauth_provider` = NULLIF(TRIM(json_extract(`extra_config`, '$.oauth.provider')), ''),
  `oauth_account_key` = NULLIF(
    TRIM(COALESCE(
      json_extract(`extra_config`, '$.oauth.accountKey'),
      json_extract(`extra_config`, '$.oauth.accountId')
    )),
    ''
  ),
  `oauth_project_id` = NULLIF(TRIM(json_extract(`extra_config`, '$.oauth.projectId')), '')
WHERE `extra_config` IS NOT NULL;
--> statement-breakpoint
CREATE INDEX `accounts_oauth_provider_idx` ON `accounts` (`oauth_provider`);
--> statement-breakpoint
CREATE INDEX `accounts_oauth_identity_idx` ON `accounts` (`oauth_provider`,`oauth_account_key`,`oauth_project_id`);
--> statement-breakpoint
CREATE UNIQUE INDEX `sites_platform_url_unique` ON `sites` (`platform`,`url`);
