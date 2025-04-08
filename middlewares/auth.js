import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();
import { PrismaClient } from "@prisma/client";


const secret = process.env.JWT_SECRET;
const prisma  = new PrismaClient();

export const isUserLoggedIn = async (req, res, next)=>{
try {
    const authorization = req.headers.authorization;
    const tokenArr = authorization.split(" ");
    const token = tokenArr[1];

    // verify the token
    const tokenData = jwt.verify(token, secret);

    // check if the user exist in database
    const user = await prisma.user.findUnique({
        where: {id: tokenData.id}
    });

    // if user if not found
    if(!user){
        return res.status(401).json({message: "Unauthorized"})
    }
    req.user = user;
    next();
} catch (error) {
    console.log(error);
    return res.status(400).json({ message: error.message });
}

}