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
router.route('/refresh').post(refresh);
router.route('/logout').post(logout);

router.route('/signup').post(registerUser);

router.route('/forgot-password').post(forgotPassword);

router.route('/activate/:token').get(activateAccount);

router.route('/password/:token').get(changePassword).post(changePassword);

export default router;
