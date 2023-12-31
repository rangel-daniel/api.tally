import { Router } from 'express';
import { createPoll, getPoll, getPolls, rmPoll } from '../controllers/poll';
import { verifyJwt } from '../middleware/verifyJwt';

const router = Router();

router.route('/').post(verifyJwt, createPoll).get(verifyJwt, getPolls);
router.route('/:pid').delete(verifyJwt, rmPoll).get(getPoll);

export default router;
