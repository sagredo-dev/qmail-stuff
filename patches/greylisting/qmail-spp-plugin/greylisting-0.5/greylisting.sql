#######################################################################
# Database definitions
#######################################################################

# contains white-/blacklists
CREATE TABLE `greylisting_lists`
(
  `id` int unsigned NOT NULL auto_increment, # unique id
  `ipaddr` varchar(43),                      # IPv4/IPv6 IP-Address or CIDR notation in ascii
  `ipaddr_start` varbinary(16),              # first IP-Address in range (binary, calculated by trigger)
  `ipaddr_end` varbinary(16),                # last IP-Address in range (binary, calculated by trigger)
  `ipaddr_prefixsize` tinyint unsigned,      # cidr prefix size (1-128, calculated by trigger)
  `rcpt_to` varchar(255) default NULL,       # the recipient address
  `block_expires` datetime NOT NULL,         # the time that an initial block will/did expire
  `record_expires` datetime NOT NULL,        # the time after which this record is ignored
  `create_time` timestamp NOT NULL default CURRENT_TIMESTAMP, # timestamp of this record
  `last_update` timestamp NOT NULL default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP, # timestamp of last change to this record
  `comment` varchar(255) NOT NULL,           # useable for comments
  PRIMARY KEY (`id`),
  KEY `ipaddr_start` (`ipaddr_start`),
  KEY `ipaddr_end` (`ipaddr_end`),
  KEY `rcpt_to` (`rcpt_to`(20))
);

# triggers for autocreation of ipaddr_start, ipaddr_end and ipaddr_prefixsize
DELIMITER ;;
CREATE TRIGGER `greylisting_lists_insert` BEFORE INSERT ON `greylisting_lists`
FOR EACH ROW
BEGIN
  DECLARE bits SMALLINT;
  DECLARE CONTINUE HANDLER FOR 1305 SET NEW.`ipaddr_start` = NULL;

  SET @base = 32;
  IF !INSTR(NEW.`ipaddr`, '.') THEN
    SET @base = 128;
  END IF;

  IF NEW.`ipaddr` IS NULL THEN
    SET NEW.`ipaddr_start` = 0;
    SET NEW.`ipaddr_end` = 0;
    SET NEW.`ipaddr_prefixsize` = 0;
  ELSEIF INSTR(NEW.`ipaddr`, '/') THEN
    SET NEW.`ipaddr_start` = INET6_ATON(SUBSTRING_INDEX(NEW.`ipaddr`, '/', 1));

    SET NEW.`ipaddr_prefixsize` = SUBSTRING_INDEX(NEW.`ipaddr`, '/', -1);
    SET bits = @base - NEW.`ipaddr_prefixsize`;
    SET @ip = HEX(NEW.`ipaddr_start`);
    SET @pos = LENGTH(@ip);
    SET @ipaddr_end = '';
    WHILE bits > 0 DO
      SET @newdigit = HEX(CONV(SUBSTRING(@ip, @pos, 1), 16, 10) | POW(2, LEAST(4, bits)) - 1);
      SET @ipaddr_end = CONCAT(@newdigit, @ipaddr_end);
      SET bits = bits - 4;
      SET @pos = @pos - 1;
    END WHILE;
    SET NEW.`ipaddr_end` = UNHEX(CONCAT(SUBSTRING(@ip, 1, @pos), @ipaddr_end));
  ELSE
    SET NEW.`ipaddr_start` = INET6_ATON(NEW.`ipaddr`);
    SET NEW.`ipaddr_end` = NEW.`ipaddr_start`;
    SET NEW.`ipaddr_prefixsize` = @base;
  END IF;
END ;;

CREATE TRIGGER `greylisting_lists_update` BEFORE UPDATE ON `greylisting_lists`
FOR EACH ROW
BEGIN
  DECLARE bits SMALLINT;
  DECLARE CONTINUE HANDLER FOR 1305 SET NEW.`ipaddr_start` = NULL;

  SET @base = 32;
  IF !INSTR(NEW.`ipaddr`, '.') THEN
    SET @base = 128;
  END IF;

  IF NEW.`ipaddr` IS NULL THEN
    SET NEW.`ipaddr_start` = 0;
    SET NEW.`ipaddr_end` = 0;
    SET NEW.`ipaddr_prefixsize` = 0;
  ELSEIF INSTR(NEW.`ipaddr`, '/') THEN
    SET NEW.`ipaddr_start` = INET6_ATON(SUBSTRING_INDEX(NEW.`ipaddr`, '/', 1));

    SET NEW.`ipaddr_prefixsize` = SUBSTRING_INDEX(NEW.`ipaddr`, '/', -1);
    SET bits = @base - NEW.`ipaddr_prefixsize`;
    SET @ip = HEX(NEW.`ipaddr_start`);
    SET @pos = LENGTH(@ip);
    SET @ipaddr_end = '';
    WHILE bits > 0 DO
      SET @newdigit = HEX(CONV(SUBSTRING(@ip, @pos, 1), 16, 10) | POW(2, LEAST(4, bits)) - 1);
      SET @ipaddr_end = CONCAT(@newdigit, @ipaddr_end);
      SET bits = bits - 4;
      SET @pos = @pos - 1;
    END WHILE;
    SET NEW.`ipaddr_end` = UNHEX(CONCAT(SUBSTRING(@ip, 1, @pos), @ipaddr_end));
  ELSE
    SET NEW.`ipaddr_start` = INET6_ATON(NEW.`ipaddr`);
    SET NEW.`ipaddr_end` = NEW.`ipaddr_start`;
    SET NEW.`ipaddr_prefixsize` = @base;
  END IF;
END ;;
DELIMITER ;

# contains data inserted during greylisting
CREATE TABLE `greylisting_data`
(
  `id` bigint unsigned NOT NULL auto_increment, # unique triplet id
  `relay_ip` varbinary(16),                     # sending relay in IPv4/IPv6 in binary
  `mail_from` varchar(255) default NULL,        # ascii address of sender
  `rcpt_to` varchar(255) default NULL,          # the recipient address.
  `block_expires` datetime NOT NULL,            # the time that an initial block will/did expire
  `record_expires` datetime NOT NULL,           # the time after which this record is ignored
  `blocked_count` int unsigned NOT NULL default '0', # num of blocked attempts to deliver
  `passed_count`  int unsigned NOT NULL default '0', # num of passed attempts we have allowed
  `aborted_count` int unsigned NOT NULL default '0', # num of attempts we have passed, but were later aborted
  `create_time` timestamp NOT NULL default CURRENT_TIMESTAMP, # timestamp of this record
  `last_update` timestamp NOT NULL default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP, # timestamp of last change to this record
  PRIMARY KEY (`id`),
  KEY `relay_ip` (`relay_ip`),
  KEY `mail_from` (`mail_from`(20)),            # To keep the index size down, only index first 20 chars
  KEY `rcpt_to` (`rcpt_to`(20))
);

# Example IP based wildcard whitelist + blacklist
#INSERT INTO `greylisting_lists` VALUES (0, "127.0.0.1", NULL, NULL, NULL, NULL, "0000-00-00 00:00:00", "9999-12-31 23:59:59", NOW(), NOW(), 'whitelist for 127.0.0.1');
#INSERT INTO `greylisting_lists` VALUES (0, "192.168.1.0/24", NULL, NULL, NULL, NULL, "9999-12-31 23:59:59", "9999-12-31 23:59:59", NOW(), NOW(), 'blacklist for 192.168.1.0/24');

# Example IPv6 based wildcard whitelist + blacklist
#INSERT INTO `greylisting_lists` VALUES (0, "2001:0db8:85a3:08d3:1319:8a2e:0370:7344", NULL, NULL, NULL, NULL, "0000-00-00 00:00:00", "9999-12-31 23:59:59", NOW(), NOW(), 'whitelist for 2001:0db8:85a3:08d3:1319:8a2e:0370:7344');
#INSERT INTO `greylisting_lists` VALUES (0, "2001:0db8:85a3::/48", NULL, NULL, NULL, NULL, "9999-12-31 23:59:59", "9999-12-31 23:59:59", NOW(), NOW(), 'blacklist for 2001:0db8:85a3::/48');

# Example domain based wildcard whitelist + blacklist
#INSERT INTO `greylisting_lists` VALUES (0, NULL, NULL, NULL, NULL, "domain.com", "0000-00-00 00:00:00", "9999-12-31 23:59:59", NOW(), NOW(), 'whitelist for *@domain.com');
#INSERT INTO `greylisting_lists` VALUES (0, NULL, NULL, NULL, NULL, "sub.domain.com", "9999-12-31 23:59:59", "9999-12-31 23:59:59", NOW(), NOW(), 'blacklist for *@sub.domain.com');
