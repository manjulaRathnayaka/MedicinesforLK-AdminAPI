CREATE TABLE IF NOT EXISTS SUPPLIER (
             SUPPLIERID INT NOT NULL AUTO_INCREMENT,
             `NAME` VARCHAR (255) NOT NULL,
             SHORTNAME VARCHAR (25) NOT NULL,
             EMAIL VARCHAR (50) NOT NULL,             
             PHONENUMBER VARCHAR (20) NOT NULL,
             PRIMARY KEY (`NAME`),
             UNIQUE(SUPPLIERID)
)ENGINE INNODB;

CREATE TABLE IF NOT EXISTS MEDICAL_ITEM (
             ITEMID INT NOT NULL AUTO_INCREMENT,
             `NAME` VARCHAR (255) NOT NULL,
             `TYPE` ENUM('Device', 'Medicine'),
             UNIT VARCHAR (50) NOT NULL,
             UNIQUE(ITEMID),
             PRIMARY KEY (`NAME`, `TYPE`)
)ENGINE INNODB;

CREATE TABLE IF NOT EXISTS BENEFICIARY (
             BENEFICIARYID INT NOT NULL AUTO_INCREMENT,
             `NAME` VARCHAR (255) NOT NULL,
             SHORTNAME VARCHAR (255) NOT NULL,
             EMAIL VARCHAR (50) NOT NULL,             
             PHONENUMBER VARCHAR (20) NOT NULL,
             PRIMARY KEY (`NAME`),
             UNIQUE(BENEFICIARYID)
)ENGINE INNODB;

CREATE TABLE IF NOT EXISTS DONOR (
             DONORID INT NOT NULL AUTO_INCREMENT,
             ORGNAME VARCHAR (255) NOT NULL,
             ORGLINK VARCHAR (255) NOT NULL,
             EMAIL VARCHAR (50) NOT NULL,             
             PHONENUMBER VARCHAR (20) NOT NULL,
             PRIMARY KEY (ORGNAME),
             UNIQUE(DONORID)
)ENGINE INNODB;

CREATE TABLE IF NOT EXISTS MEDICAL_NEED (
             NEEDID INT NOT NULL AUTO_INCREMENT,
             ITEMID INT NOT NULL,
             BENEFICIARYID INT NOT NULL,
             `PERIOD` DATE NOT NULL,
             NEEDEDQUANTITY INT NOT NULL DEFAULT 0,
             REMAININGQUANTITY INT NOT NULL DEFAULT 0,
             URGENCY ENUM('Normal', 'Critical', 'Urgent'),
             PRIMARY KEY (ITEMID, BENEFICIARYID, `PERIOD`),
             UNIQUE(NEEDID),
             FOREIGN KEY (BENEFICIARYID) REFERENCES BENEFICIARY(BENEFICIARYID),       
             FOREIGN KEY (ITEMID) REFERENCES MEDICAL_ITEM(ITEMID)
)ENGINE INNODB;

CREATE TABLE IF NOT EXISTS QUOTATION (
             QUOTATIONID INT NOT NULL AUTO_INCREMENT,
             SUPPLIERID INT NOT NULL,
             ITEMID INT NOT NULL,
             BRANDNAME VARCHAR (255) NOT NULL,
             AVAILABLEQUANTITY INT NOT NULL DEFAULT 0,
            `PERIOD` DATE NOT NULL,
            `EXPIRYDATE` DATE NOT NULL,
             UNITPRICE DECIMAL(15, 2) NOT NULL DEFAULT 0,
             REGULATORYINFO VARCHAR (100) NOT NULL,
             PRIMARY KEY (SUPPLIERID, ITEMID, `PERIOD`),
             UNIQUE(QUOTATIONID),
             FOREIGN KEY (SUPPLIERID) REFERENCES SUPPLIER(SUPPLIERID), 
             FOREIGN KEY (ITEMID) REFERENCES MEDICAL_ITEM(ITEMID)
)ENGINE INNODB;

CREATE TABLE IF NOT EXISTS AID_PACKAGE (
             PACKAGEID INT NOT NULL AUTO_INCREMENT,
             NAME VARCHAR (225) NOT NULL,
             `DESCRIPTION` VARCHAR (1500) NOT NULL,
             `STATUS` ENUM('Draft', 'Published',
             	 'Awaiting Payment', 'Ordered', 'Shipped',
             	 'Received at MoH', 'Delivered'),
             PRIMARY KEY (PACKAGEID),
             UNIQUE(PACKAGEID)
)ENGINE INNODB;

CREATE TABLE IF NOT EXISTS AID_PACKAGE_ITEM (
			 PACKAGEITEMID INT NOT NULL AUTO_INCREMENT,
             PACKAGEID INT NOT NULL,
             QUOTATIONID INT NOT NULL,
             NEEDID INT NOT NULL,
             QUANTITY INT NOT NULL DEFAULT 0,
             TOTALAMOUNT DECIMAL(15, 2) NOT NULL DEFAULT 0,
             PRIMARY KEY (QUOTATIONID, NEEDID, PACKAGEID),
             UNIQUE(PACKAGEITEMID),
             FOREIGN KEY (QUOTATIONID) REFERENCES QUOTATION(QUOTATIONID),
             FOREIGN KEY (NEEDID) REFERENCES MEDICAL_NEED(NEEDID), 
             FOREIGN KEY (PACKAGEID) REFERENCES AID_PACKAGE(PACKAGEID)
)ENGINE INNODB;

CREATE TABLE IF NOT EXISTS AID_PACKAGE_UPDATE (
             PACKAGEUPDATEID INT NOT NULL AUTO_INCREMENT,
             PACKAGEID INT NOT NULL,
             UPDATECOMMENT VARCHAR (1500) NOT NULL,
             `DATETIME`  DATETIME NOT NULL,
             PRIMARY KEY (PACKAGEID, PACKAGEUPDATEID),
             UNIQUE(PACKAGEUPDATEID),
             FOREIGN KEY (PACKAGEID) REFERENCES AID_PACKAGE(PACKAGEID)
)ENGINE INNODB;

CREATE TABLE IF NOT EXISTS PLEDGE (
             PLEDGEID INT NOT NULL AUTO_INCREMENT,
             PACKAGEID INT NOT NULL,
             DONORID INT NOT NULL,
             AMOUNT DECIMAL(15, 2) NOT NULL DEFAULT 0,
             `STATUS` ENUM('Pledged', 'Payment Initiated', 'Payment Confirmed'),
             PRIMARY KEY (PACKAGEID, DONORID),
             UNIQUE(PLEDGEID),
             FOREIGN KEY (PACKAGEID) REFERENCES AID_PACKAGE(PACKAGEID),
             FOREIGN KEY (DONORID) REFERENCES DONOR(DONORID)
)ENGINE INNODB;

CREATE TABLE IF NOT EXISTS PLEDGE_UPDATE (
             PLEDGEUPDATEID INT NOT NULL AUTO_INCREMENT,
             PLEDGEID INT NOT NULL,
             UPDATECOMMENT VARCHAR (1500) NOT NULL,
             `DATETIME`  DATETIME NOT NULL,
             PRIMARY KEY (PLEDGEID, PLEDGEUPDATEID),
             UNIQUE(PLEDGEUPDATEID),
             FOREIGN KEY (PLEDGEID) REFERENCES PLEDGE(PLEDGEID)
)ENGINE INNODB;

ALTER TABLE AID_PACKAGE_ITEM ADD INITIALQUANTITY int NOT NULL DEFAULT '0';

ALTER TABLE Pledge DROP CONSTRAINT pledge_ibfk_2;

ALTER TABLE Pledge MODIFY DONORID VARCHAR(48) NOT NULL;

ALTER TABLE QUOTATION ADD REMAININGQUANTITY INT NOT NULL DEFAULT 0;