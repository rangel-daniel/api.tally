import { Router } from 'express';
import {
    registerUser,
    activateAccount,
    changePassword,
    forgotPassword,
    login,
    refresh,
    logout,
} from '../controllers/auth';
import { loginLimiter } from '../middleware/loginLimiter';

const router = Router();

router.route('/').post(loginLimiter, login);

router.route('/refresh').get(refresh);

router.route('/logout').post(logout);

router.route('/signup').post(registerUser);

router.route('/forgot-password').post(forgotPassword);

router.route('/activate/:token').post(activateAccount);

router.route('/password/:token').post(changePassword);

export default router;
