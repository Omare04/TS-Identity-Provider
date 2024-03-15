import express, { Request, Response, NextFunction } from "express";
import mysql, { Pool, PoolConnection } from "mysql2/promise";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import cors from "cors";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import axios from "axios";
import crypto from "crypto";

dotenv.config();


const router = express();
router.use(bodyParser.urlencoded({ extended: true }));
router.use(cookieParser());
router.use(bodyParser.json());

const origin = undefined

router.use(
  cors({
    origin: origin,
    methods: ["GET", "POST"],
    credentials: true,
  })
);




export default router;
