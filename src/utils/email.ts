import { Transporter } from 'nodemailer';
import getTransporter from '../config/transporter';
import fs from 'fs';
import path from 'path';
import ejs from 'ejs';

export const sendEmail = async (
    userInfo: { email: string; name: string },
    secrete: { isPassword: boolean; token: string },
) => {
    const PASSWORD = {
        title: 'Reset your password',
        body: 'A password reset request has been submitted for your account. To update your password, click the button below.',
        btnLabel: 'Reset password',
    };

    const ACTIVATE = {
        title: 'Activate your account',
        body: 'To activate your account we need to verify your email address. Please click the button below to complete the process.',
        btnLabel: 'Activate account',
    };

    const EMAIL = process.env.EMAIL;
    const URL =
        process.env.NODE_ENV === 'Dev'
            ? 'http://localhost:5173/'
            : 'https://tally-app.live/';

    try {
        const transporter: Error | Transporter = await getTransporter();

        if (transporter instanceof Error) {
            return transporter;
        }

        const { email, name } = userInfo;
        const { isPassword, token } = secrete;

        const subject = isPassword ? PASSWORD.title : ACTIVATE.title;
        const link = URL + (isPassword ? 'password/' : 'email/') + token;

        const templatePath = path.join(
            __dirname,
            '..',
            'templates',
            'emailTemplate.html',
        );
        const emailTemplate = fs.readFileSync(templatePath, 'utf-8');
        const renderedTemplate = ejs.render(emailTemplate, {
            link,
            name,
            ...(isPassword ? PASSWORD : ACTIVATE),
        });

        const mailOptions = {
            from: `Tally <${EMAIL}>`,
            to: email,
            subject,
            html: renderedTemplate,
        };

        return await transporter.sendMail(mailOptions);
    } catch (error) {
        console.error(error);
        return error;
    }
};
