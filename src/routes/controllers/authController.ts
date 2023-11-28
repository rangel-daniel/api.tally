import { Request, Response } from 'express';
import asyncHandler from 'express-async-handler';
import { EmailPasswordAuth, EmailPasswordUser, User } from '../../models/User';
import { sendEmail } from '../../utils/email';
import Secrete from '../../models/secrete';
import path from 'path';

const emailUser = async (type: 'activate'|'password', user: EmailPasswordUser) =>{
	const { _id: uid, email, name } = user;
	const userInfo = { uid, email, name };

	const secrete = await Secrete.create({ type, uid });

	await sendEmail(userInfo, secrete);
};

export const registerUser = asyncHandler(async (req: Request, res: Response) => {
	const { email: _email, name: _name, password } = req.body;
	const user = await EmailPasswordAuth.create({ email: _email, name: _name, password, secrete: { type: 'activate' } });

	await emailUser('activate',user);

	res.json({ message: 'Successful registration!' });
});

export const activateAccount = asyncHandler(async (req: Request, res: Response) => {
	const { token } = req.params;

	const secrete = await Secrete.findOne({ token }).lean();

	if (!secrete || secrete.type !== 'activate') {
		res.status(404).json({ message: 'Invalid token.' });
		return;
	}

	const user = await EmailPasswordAuth.findById(secrete.uid).select('email tempEmail');

	if (!user || !user.tempEmail) {
		res.status(404).json({ message: 'Invalid token.' });
		return;
	}

	if (user.tempEmail !== 'new') {
		user.email = user.tempEmail;
	}

	user['tempEmail'] = undefined;
	await Secrete.deleteOne({_id: secrete._id});
	await user.save();

	res.json({ message: 'Account successfully activated!' });
});

export const changePassword = asyncHandler(async (req: Request, res: Response) => {
	const{method} = req;
	const { token } = req.params;

	const secrete = await Secrete.findOne({ token }).lean();
	const validUser = await User.exists({_id: secrete?.uid});

	if (!secrete || secrete.type !== 'password'|| !validUser) {
		res.status(404).json({ message: 'Invalid token.' });
		return;
	}

	if(method === 'GET'){
		res.sendFile(path.join(__dirname, '..', '..', 'templates', 'changePassword.html'));
		return;
	}
	
	const {password} = req.body;

	const user = await EmailPasswordAuth.findById(secrete.uid).select('password');

	if (!user) {
		res.status(404).json({ message: 'Invalid token.' });
		return;
	}

	user.password = password;
	await user.save();

	await Secrete.deleteOne({_id: secrete._id});

	res.json({message: 'Password updaed.'});
});

export const forgotPassword = asyncHandler(async (req:Request, res: Response ) => {
	const {email} = req.body;

	const user = await EmailPasswordAuth.findOne({email});

	if(!user){
		res.status(400).json({ message: 'User does not exist.' });
		return;
	}

	await emailUser('password',user);

	res.json({message : 'Email sent.'});
});