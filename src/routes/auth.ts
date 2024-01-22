import { Router } from 'express';
import {
    registerUser,
    getUser,
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

router.route('/').get(verifyJwt, getUser).post(loginLimiter, login);
router.route('/refresh').get(refresh);
router.route('/signup').post(registerUser);
router.route('/logout').post(logout);

router.route('/update-password').patch(verifyJwt, updatePassword);
router.route('/update-email').patch(verifyJwt, updateEmail);
router.route('/update-name').patch(verifyJwt, updateName);
router.route('/delete-account').delete(verifyJwt, deleteAccount);

router.route('/forgot-password').post(forgotPassword);
router.route('/password/:token').patch(changePasswordWithToken);

router.route('/resend-email').post(resendEmail);
router.route('/activate/:token').patch(activateAccount);

export default router;
