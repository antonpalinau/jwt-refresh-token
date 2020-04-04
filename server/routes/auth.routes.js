import { Router } from 'express';
import bcrypt from 'bcrypt';
import { check, validationResult } from 'express-validator';
import jwt from 'jsonwebtoken';
import { updateTokens } from '../helpers/authHelper';
import config from '../config';
import User from '../models/User';
import Token from '../models/Token';

const router = Router();

router.post(
    '/register',
    [
        check('email', 'Email is incorrect').isEmail(),
        check('password', 'The minimum length of password is 6 symbols').isLength({ min: 6 })
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);

            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array(), msg: 'Incorrect registration data' });
            }

            const { email, password } = req.body;
            const user = await User.findOne({ email });

            if (user) {
                return res.status(400).json({ msg: 'Email already exists' });
            }

            const hashedPassword = await bcrypt.hash(password, 12);
            const newUser = new User({ email, password: hashedPassword });
            
            await newUser.save();

            res.status(201).json({ msg: 'Registration is successful'});
        } catch (e) {
            res.status(500).json({ msg: e.message });
        }
    } 
)

router.post(
    '/login',
    [
        check('email', 'Enter the email').isEmail(),
        check('password', 'Enter the password').exists()
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);

            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array(), msg: 'Incorrect login data' });
            }

            const { email, password } = req.body;
            const user = await User.findOne({ email });

            if (!user) {
                return res.status(400).json({ msg: 'Login failed' });
            }

            const isPasswordMatch = await bcrypt.compare(password, user.password);

            if (!isPasswordMatch) {
                return res.status(400).json({ msg: 'Login failed' });
            }

            const tokens = await updateTokens(user.id);

            res.json({ tokens, userId: user.id });
        } catch (e) {
            res.status(500).json({ msg: e.message });
        }
    } 
)

router.post(
    '/tokens',
    async (req, res) => {
        try {
            const { refreshToken } = req.body;
            const payload = jwt.verify(refreshToken, config.jwt.secret);

            if (payload.type !== 'refresh') {
                return res.status(403).json({ msg: 'Invalid token '});
            }

            const token = await Token.findOne({ tokenId: payload.tokenId });

            if (!token) {
                return res.status(403).json({ msg: 'Invalid token '});
            }
            
            const tokens = await updateTokens(token.userId);

            res.json({ tokens })
        } catch (e) {
            if (e instanceof jwt.TokenExpiredError ) {
                return res.status(403).json({ msg: 'Token expired' });
            } else if (e instanceof jwt.JsonWebTokenError) {
                return res.status(403).json({ msg: 'Invalid token' });
            }
            res.status(500).json({ msg: e.message });
        }
    } 
)

export default router;