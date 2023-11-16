import { google } from 'googleapis';
import nodemailer, { Transporter } from 'nodemailer';

const ONE_MINUTE = 60 * 1000;

let transporter !: Transporter;
let accessTokenExpiration: number = 0;


const getTransporter = async (): Promise<Transporter | Error> => {
	const EMAIL = process.env.EMAIL;
	const CLIENT_ID = process.env.CLIENT_ID;
	const CLIENT_SECRETE = process.env.CLIENT_SECRETE;
	const REDIRECT_URI = process.env.REDIRECT_URI;
	const REFRESH_TOKEN = process.env.REFRESH_TOKEN;

	if (transporter && accessTokenExpiration > Date.now() + ONE_MINUTE) {
		return transporter;
	}

	const oauth = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRETE, REDIRECT_URI);
	oauth.setCredentials({ refresh_token: REFRESH_TOKEN });

	try {
		const { token, res } = await oauth.getAccessToken();

		const newTransporter = nodemailer.createTransport({
			service: 'gmail',
			auth: {
				type: 'OAuth2',
				user: EMAIL,
				clientId: CLIENT_ID,
				clientSecret: CLIENT_SECRETE,
				refreshToken: REFRESH_TOKEN,
				accessToken: token as string,
			},
		});

		transporter = newTransporter;
		accessTokenExpiration = Date.now() + res?.data.expires_in * 1000 || 0;

		return transporter;
	} catch (error) {
		console.error(error, 'Failed to initialize transporter.');
		return (error as Error);
	}

};

export default getTransporter;
