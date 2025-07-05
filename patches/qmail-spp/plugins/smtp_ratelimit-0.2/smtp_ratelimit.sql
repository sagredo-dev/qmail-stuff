#######################################################################
# Database definitions
#######################################################################

CREATE TABLE `smtp_ratelimit` (
  `user` varchar(12) NOT NULL PRIMARY KEY,
  `tokens` smallint(1) DEFAULT '0',
  `last_refill` timestamp DEFAULT CURRENT_TIMESTAMP
) ENGINE=MEMORY;
