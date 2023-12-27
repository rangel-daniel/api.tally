import { Router } from 'express';
import {
    registerUser,
    activateAccount,
    changePasswordWithToken,
    forgotPassword,
    login,
    refresh,
    logout,
    updatePassword,
    updateEmail,
} from '../controllers/auth';
import { loginLimiter } from '../middleware/loginLimiter';
import { verifyJwt } from '../middleware/verifyJwt';

const router = Router();

router.route('/').post(loginLimiter, login);

router.route('/update-password').post(verifyJwt, updatePassword);

router.route('/update-email').post(verifyJwt, updateEmail);

router.route('/logout').post(logout);

router.route('/refresh').get(refresh);

router.route('/signup').post(registerUser);

router.route('/forgot-password').post(forgotPassword);

router.route('/activate/:token').post(activateAccount);

router.route('/password/:token').post(changePasswordWithToken);

export default router;
