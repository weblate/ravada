CREATE TABLE `grant_types` (
  `id` integer NOT NULL PRIMARY KEY AUTOINCREMENT
,  `name` char(32) NOT NULL
,  `description` varchar(255) NOT NULL
,  `enabled` integer not null default 1
,    UNIQUE(`name`)
,    UNIQUE(`description`)
);
