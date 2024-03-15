import express, { Request, Response, NextFunction } from "express";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import cors from "cors";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import axios from "axios";
import crypto from "crypto";

const AuthorizationRoute = express();

async function generateRandomString(length: number): Promise<string> {
    return new Promise((resolve, reject) => {
        crypto.randomBytes(length, (err, buffer) => {
            if (err) {
                reject(err);
            } else {
                resolve(buffer.toString("hex"));
            }
        });
    });
}