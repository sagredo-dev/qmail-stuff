# update table schema
ALTER TABLE `greylisting_lists`
CHANGE `ipaddr`       `ipaddr` varchar(43),
CHANGE `ipaddr_start` `ipaddr_start` varbinary(16),
CHANGE `ipaddr_end`   `ipaddr_end` varbinary(16),
CHANGE `create_time`  `create_time` timestamp NOT NULL default CURRENT_TIMESTAMP,
ADD `ipaddr_prefixsize` tinyint unsigned AFTER `ipaddr_end`;

ALTER TABLE `greylisting_data`
CHANGE `relay_ip`      `relay_ip` varbinary(16),
CHANGE `blocked_count` `blocked_count` int unsigned NOT NULL default '0',
CHANGE `passed_count`  `passed_count`  int unsigned NOT NULL default '0',
CHANGE `aborted_count` `aborted_count` int unsigned NOT NULL default '0',
CHANGE `create_time`   `create_time` timestamp NOT NULL default CURRENT_TIMESTAMP;

# recreate trigger
DROP TRIGGER `greylisting_lists_insert`;
DROP TRIGGER `greylisting_lists_update`;

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

# temporary remove "on update"
ALTER TABLE `greylisting_lists`
CHANGE `last_update` `last_update` timestamp NOT NULL default CURRENT_TIMESTAMP;
ALTER TABLE `greylisting_data`
CHANGE `last_update` `last_update` timestamp NOT NULL default CURRENT_TIMESTAMP;

# update addresses to binary
UPDATE `greylisting_lists`
SET `ipaddr` = `ipaddr`;

UPDATE `greylisting_data`
SET `relay_ip` = INET6_ATON(`relay_ip`);

# convert timestamps to utc
UPDATE `greylisting_lists`
SET
  `block_expires` = CONVERT_TZ(`block_expires`, "SYSTEM", "+00:00"),
  `record_expires` = CONVERT_TZ(`record_expires`, "SYSTEM", "+00:00");

UPDATE `greylisting_data`
SET
  `block_expires` = CONVERT_TZ(`block_expires`, "SYSTEM", "+00:00"),
  `record_expires` = CONVERT_TZ(`record_expires`, "SYSTEM", "+00:00");

# finally add "on update" back
ALTER TABLE `greylisting_lists`
CHANGE `last_update` `last_update` timestamp NOT NULL default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP;
ALTER TABLE `greylisting_data`
CHANGE `last_update` `last_update` timestamp NOT NULL default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP;
