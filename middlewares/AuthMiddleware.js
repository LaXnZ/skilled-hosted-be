import jwt from "jsonwebtoken";

export const verifyToken = (req, res, next) => {
  const token = JSON.parse(req.cookies.jwt);

  console.log(token);

  if (!token) return res.status(401).send("You are not authenticated!");
  jwt.verify(token.jwt, process.env.JWT_KEY, async (err, payload) => {
    if (err) return res.status(403).send("Token is not valid!");
    req.userId = payload?.userId;
    next();
  });
};