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
    updateName,
    deleteAccount,
    resendEmail,
} from '../controllers/auth';
import { loginLimiter } from '../middleware/loginLimiter';
import { verifyJwt } from '../middleware/verifyJwt';

const router = Router();

router.route('/').post(loginLimiter, login);
router.route('/logout').post(logout);

router.route('/update-password').post(verifyJwt, updatePassword);
router.route('/update-email').post(verifyJwt, updateEmail);
router.route('/update-name').post(verifyJwt, updateName);
router.route('/delete-account').post(verifyJwt, deleteAccount);

router.route('/forgot-password').post(forgotPassword);

router.route('/signup').post(registerUser);

router.route('/refresh').get(refresh);

router.route('/resend-email').post(resendEmail);

router.route('/activate/:token').post(activateAccount);

router.route('/password/:token').post(changePasswordWithToken);

export default router;
