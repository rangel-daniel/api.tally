import { Router } from 'express';
import {
    createPoll,
    getPoll,
    getPolls,
    resetPoll,
    rmPoll,
} from '../controllers/poll';
import { verifyJwt } from '../middleware/verifyJwt';
import { vote } from '../controllers/tally';

const router = Router();

router.route('/').post(verifyJwt, createPoll).get(verifyJwt, getPolls);
router.route('/tally').post(verifyJwt, vote);
router.route('/reset').patch(verifyJwt, resetPoll);
router.route('/:pid').delete(verifyJwt, rmPoll).get(getPoll);
export default router;
