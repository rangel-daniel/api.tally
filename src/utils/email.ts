import { Transporter } from 'nodemailer';
import getTransporter from '../config/transporter';
import fs from 'fs';
import path from 'path';
import ejs from 'ejs';
import { Types } from 'mongoose';


export const sendEmail = async (userInfo: { _id: Types.ObjectId, email: string, name: string }, secrete: { type: 'activate' | 'password', _id: Types.ObjectId }) => {
	const EMAIL = process.env.EMAIL;
	const URL = process.env.NODE_ENV === 'Dev' ? 'http://localhost:3000/' : 'https://api.tally-app.live/';
	try {
		const transporter: Error | Transporter = await getTransporter();

		if (transporter instanceof Error) {
			return transporter;
		}

		const { _id: uid, email, name } = userInfo;
		const { type, _id: token } = secrete;

		const subject = type === 'activate' ? 'Activate your account' : 'Password reset';
		const link = URL + `${type}/${uid}/${token}/`;
		const templatePath = path.join(__dirname, '..', 'templates', type === 'activate' ? 'activateEmail.html' : 'passwordEmail.html');
		const emailTemplate = fs.readFileSync(templatePath, 'utf-8');
		const renderedTemplate = ejs.render(emailTemplate, {
			link,
			name
		});

		const mailOptions = {
			from: `Tally <${EMAIL}>`,
			to: email,
			subject,
			html: renderedTemplate
		};

		return await transporter.sendMail(mailOptions);
	} catch (error) {
		console.error(error);
		return error;
	}
};
