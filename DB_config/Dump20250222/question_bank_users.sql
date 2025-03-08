-- MySQL dump 10.13  Distrib 8.0.40, for Win64 (x86_64)
--
-- Host: localhost    Database: question_bank
-- ------------------------------------------------------
-- Server version	8.0.40

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` varchar(50) NOT NULL,
  `otp` varchar(6) DEFAULT NULL,
  `status` enum('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  `is_verified` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=26 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (2,'srushtibhosale436@gmail.com','srushti_45','scrypt:32768:8:1$mjXXa3mK2X4JLQWd$47c21b0f4d9b2375f954c6eff9e38954cf1f9bccab26e1a774a9ea4ad3e63cd4c57e1511bba6e05e064f0d9dbdabf61353864886bd081ead1d2d0b52b251702a','Higher Authority',NULL,'approved',0),(3,'pratiksha27@gmail.com','pratiksha27','1234567','Teacher',NULL,'rejected',0),(5,'shreyapatil13@gmail.com','text','567','Teacher',NULL,'approved',0),(7,'vedikapatil2713@gmail.com','vedika2724','scrypt:32768:8:1$AXQrkgcIFxqGe6eG$5892d6435cdeffdbbb44a1edf26f6e5bb8477587944d8d58f57e019c45e023b8a261a952002019ccfef0bb52e57e730120768a2db4993750d26d39882931063a','Teacher',NULL,'approved',0),(8,'spshreyapatil135@gmail.com','shreya@123','scrypt:32768:8:1$oLwK4YmUTYIWIPe9$5d9d6ef6a856db8a65c184eb2a2f50bde5e930d15a7bdf8f6bd1b2f75a731170a8215f37a344727c43ffb5e1e87bb456eb2bc44ab96d3636054ff2afb25bc8ac','Teacher',NULL,'approved',0),(12,'suhanigharge25@gmail.com','suhani25','pbkdf2:sha256:1000000$6y8fFhvF$f6b2609a293d042147ee3f3e7625b62508c7fd0328f2f4925146929b0b868735','Teacher','3597','approved',0),(13,'harshrajburungale9860@gmail.com','harshu99','scrypt:32768:8:1$HaIxtijtg0uABhj3$e2f7311218d231fd60f088626917e737cee4c7ce5d901d85209673152f4688ed47bce11caa47704fa5b7ca64b119a988408c62b59d56719650f423151821608d','Teacher',NULL,'rejected',0),(17,'vedika123@gmail.com','admin','scrypt:32768:8:1$UgRu0gY6cwywLhAI$ef56787e5ac1023fceafd0a44567af1004187fd3f7297954240926a4980341f51db5ccaa07f4bf517b5d5efc16bc186e60fbf4bba689c0dacec23395ecd49cb8','Admin',NULL,'pending',0),(22,'komalpatil89522@gmail.com','komal','scrypt:32768:8:1$RbznrBdy0w7QRA93$ca01d2c3fa8a9d73fa2b0c6ae51d1fa43ee1c1b6c8c2560fd619384b1dcd1ad9d2544f88de2e992eb9a44c641a64b946665392aa30fab942db5069369807659b','Admin',NULL,'pending',0),(24,'info.vedikapatil@gmail.com','veduu','pbkdf2:sha256:1000000$W8Lk5y5P$9570411d82763f2fed06224b627883d992212a47072856cf4688b1a14f8449d4','Admin','8135','approved',1),(25,'saurabhpatil4107@gmail.com','Saurabh27','pbkdf2:sha256:1000000$ocEWg2G9$8d9084e3c3f16a81bb592e02dd788bd6d97a7e647e1e0fec271dfd3dbec41105','Teacher','9557','approved',1);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-02-22 16:58:46
