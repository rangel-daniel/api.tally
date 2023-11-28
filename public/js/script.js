const postPassword = async (event) => {
	event.preventDefault();

	const button = document.getElementById('submit');
	button.disabled = true;

	const password = document.getElementById('password').value;
	const body = JSON.stringify({password});
	
	const endpoint = window.location.href;

	console.log(password, body, {body});
	const data = await fetch(endpoint, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body
	});

	const displayStatus = document.getElementById('displayStatus');
	displayStatus.classList = [];

	if (data.status === 200) {
		displayStatus.innerHTML = '✅ Password updated!';
		displayStatus.classList.add('success');
		button.removeAttribute('style');
		button.classList.add('disable-btn');
		return;
	}

	displayStatus.classList.add('error');

	displayStatus.innerHTML =data.status === 400? '❌ Invalid password.': '❌ Inavlid token.';
	button.disabled = false;
};