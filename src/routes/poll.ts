import { Router } from 'express';
import {
    createPoll,
    editPoll,
    getPoll,
    getPolls,
    resetPoll,
    rmPoll,
} from '../controllers/poll';
import { verifyJwt } from '../middleware/verifyJwt';
import { vote } from '../controllers/tally';

const router = Router();

router
    .route('/')
    .post(verifyJwt, createPoll)
    .patch(verifyJwt, editPoll)
    .delete(verifyJwt, rmPoll)
    .get(getPoll);

router.route('/reset').patch(verifyJwt, resetPoll);
router.route('/tally').post(verifyJwt, vote);
router.route('/user').get(verifyJwt, getPolls);

export default router;
