import { chromium } from 'playwright'

const browser = await chromium.launch({
	headless: true,
	args: ['--disable-dev-shm-usage']
})

function wait(ms) {
	return new Promise(resolve => setTimeout(resolve, ms))
}

export async function visit(id, flag) {
	const view = await browser.newContext()
	const page = await view.newPage()

	page.on('dialog', async dialog => {
		await dialog.dismiss()
	})

	await page.route('**/*', async route => {
		const req = route.request()
		const url = new URL(req.url())

		if (url.origin === 'http://127.0.0.1:3000') {
			await route.continue()
			return
		}

		if (req.resourceType() === 'image') {
			await route.continue()
			return
		}

		await route.abort()
	})

	try {
		await view.addCookies([{
			name: 'session',
			value: flag,
			url: 'http://127.0.0.1:3000',
			sameSite: 'Lax'
		}])

		await page.goto(`http://127.0.0.1:3000/post/${id}`, {
			waitUntil: 'domcontentloaded',
			timeout: 10000
		}).catch(() => {})

		await wait(4000)
	} finally {
		await view.close()
	}
}
