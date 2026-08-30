ALTER TABLE `sites` ADD `post_refresh_probe_enabled` integer DEFAULT false;
--> statement-breakpoint
ALTER TABLE `sites` ADD `post_refresh_probe_model` text DEFAULT '';
--> statement-breakpoint
ALTER TABLE `sites` ADD `post_refresh_probe_scope` text DEFAULT 'single';
