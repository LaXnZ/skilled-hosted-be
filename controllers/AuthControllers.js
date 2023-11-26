import { Prisma, PrismaClient } from "@prisma/client";
import { genSalt, hash, compare } from "bcrypt";
import jwt from "jsonwebtoken";
import { renameSync } from "fs";

const generatePassword = async (password) => {
  const salt = await genSalt();
  return await hash(password, salt);
};

const maxAge = 3 * 24 * 60 * 60;
const createToken = (email, userId) => {
  // @ts-ignore
  return jwt.sign({ email, userId }, process.env.JWT_KEY, {
    expiresIn: maxAge,
  });
};

export const signup = async (req, res, next) => {
  try {
    const prisma = new PrismaClient();
    const { email, password } = req.body;
    if (email && password) {
      const user = await prisma.user.create({
        data: {
          email,
          password: await generatePassword(password),
        },
      });
      return res.status(201).json({
        user: { id: user?.id, email: user?.email },
        jwt: createToken(email, user.id),
      });
    } else {
      return res.status(400).send("Email and Password Required");
    }
  } catch (err) {
    console.log(err);
    if (err && err instanceof Prisma.PrismaClientKnownRequestError) {
      if (err.code === "P2002") {
        return res.status(400).send("Email Already Registered");
      }
    } else {
      return res.status(500).send("Internal Server Error");
    }
    throw err;
  }
};

export const login = async (req, res, next) => {
  try {
    const prisma = new PrismaClient();
    const { email, password } = req.body;
    if (email && password) {
      const user = await prisma.user.findUnique({
        where: {
          email,
        },
      });
      if (!user) {
        return res.status(404).send("User not found");
      }

      const auth = await compare(password, user.password);
      if (!auth) {
        return res.status(400).send("Invalid Password");
      }

      return res.status(200).json({
        user: { id: user?.id, email: user?.email },
        jwt: createToken(email, user.id),
      });
    } else {
      return res.status(400).send("Email and Password Required");
    }
  } catch (err) {
    return res.status(500).send("Internal Server Error");
  }
};

export const getUserInfo = async (req, res, next) => {
  try {
    if (req.userId) {
      const prisma = new PrismaClient();
      const user = await prisma.user.findUnique({
        where: {
          id: req.userId,
        },
      });
      
      // Check if the user exists before accessing its properties
      if (user) {
        delete user.password;
        return res.status(200).json({
          user: {
            id: user.id,
            email: user.email,
            image: user.profileImage,
            username: user.username,
            fullName: user.fullName,
            description: user.description,
            isProfileSet: user.isProfileInfoSet,
          },
        });
      } else {
        // Handle the case where the user with the specified ID is not found
        return res.status(404).json({ error: "User not found" });
      }
    } else {
      // Handle the case where req.userId is not defined
      return res.status(400).json({ error: "User ID not provided" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error", err?.message);
  }
};




export const setUserInfo = async (req, res, next) => {
  try {
    if (req?.userId) {
      const { userName, fullName, description } = req.body;

      // Input validation
      if (!(userName && fullName && description)) {
        return res.status(400).json({ error: "Username, Full Name, and description are required." });
      }

      const prisma = new PrismaClient();

      // Check if the username is already taken
      const userNameValid = await prisma.user.findUnique({
        where: { username: userName },
      });
      
      if (userNameValid) {
        return res.status(200).json({ userNameError: true });
      }

      // Update user profile information
      await prisma.user.update({
        where: { id: req.userId },
        data: {
          username: userName,
          fullName,
          description,
          isProfileInfoSet: true,
        },
      });

      // Respond with success
      return res.status(200).json({ success: true, message: "Profile data updated successfully." });
    } else {
      return res.status(400).json({ error: "User ID not provided." });
    }
  } catch (err) {
    console.error(err);

    // Handle Prisma errors
    if (err instanceof Prisma.PrismaClientKnownRequestError) {
      if (err.code === "P2002") {
        return res.status(400).json({ userNameError: true });
      }
    }

    // Handle other errors
    return res.status(500).json({ error: "Internal Server Error" });
  }
};


export const setUserImage = async (req, res, next) => {
  try {
    if (req.file) {
      if (req?.userId) {
        const date = Date.now();
        let fileName = "uploads/profiles/" + date + req.file.originalname;
        renameSync(req.file.path, fileName);
        const prisma = new PrismaClient();

        await prisma.user.update({
          where: { id: req.userId },
          data: { profileImage: fileName },
        });
        return res.status(200).json({ img: fileName });
      }
      return res.status(400).send("Cookie Error.");
    }
    return res.status(400).send("Image not inclued.");
  } catch (err) {
    console.log(err);
    res.status(500).send("Internal Server Occured");
  }
};
