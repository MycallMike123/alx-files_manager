// controllers/AuthController.js

import { v4 as uuidv4 } from 'uuid';
import sha1 from 'sha1';
import dbClient from '../utils/db';
import redisClient from '../utils/redis';

class AuthController {
  // statci method to handle user login and token generation
  static async getConnect(req, res) {
    // extract the authorization header from the request
    const authHeader = req.headers.authorization;

    // check if auth header is missing or doesn't start with 'Basic '
    if (!authHeader || !authHeader.startsWith('Basic ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // extract the base64 encoded credentials from the auth header
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString(
      'ascii',
    );

    // split decoded credentials into email and password
    const [email, password] = credentials.split(':');

    if (!email || !password) {
      // check if email or password is missing
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // hash the provided password
    const hashedPassword = sha1(password);

    // search for a user with the provided email & hashed password
    const user = await dbClient.db
      .collection('users')
      .findOne({ email, password: hashedPassword });

    if (!user) {
      // return 401 if no user is found with the provided email & password
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = uuidv4(); // generate unique token using uuidv4
    const tokenKey = `auth_${token}`; // create key for storing token in redis
    // store user's ID in redis with generated token as key to expire in 24 hours
    await redisClient.set(tokenKey, user._id.toString(), 86400);

    return res.status(200).json({ token });
  }

  // static method to handle user logout and token invalidation
  static async getDisconnect(req, res) {
    // extract token from the x-token header
    const token = req.headers['x-token'];
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // create key for token stored in redis
    const tokenKey = `auth_${token}`;

    // get user ID linked to token
    const userId = await redisClient.get(tokenKey);

    // return 401 if no user is linked to the provided token
    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Delete token from redis - logging out user
    await redisClient.del(tokenKey);
    return res.status(204).send();
  }
}

// export AuthController class
export default AuthController;
