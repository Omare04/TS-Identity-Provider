import express, { Request, Response, NextFunction } from "express";
import { User } from "./helper";
import { dbPool } from "./db";
import bcrypt from 'bcrypt'




const registrationRouter = express();

registrationRouter.post("/register", async (req: Request, res: Response) => {
    try {
        const { fname, lname, email, password, position } = req.body;
        const salt: string = await bcrypt.genSalt();
        const hashedPassword: string = await bcrypt.hash(password, salt);
        const query: string =
            "INSERT INTO users (fname, lname, email, password, position) VALUES (?, ?, ?, ?, ?)";
        await dbPool.query(query, [fname, lname, email, hashedPassword, position]);
        res.sendStatus(200);
    } catch (error) {
        console.error("Error occurred during registration:", error);
        res.status(500).send("Internal Server Error");
    }
});