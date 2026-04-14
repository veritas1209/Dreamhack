import crypto from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import express from 'express'
import multer from 'multer'
import { chromium } from 'playwright'
import { visit } from './bot.js'

const app = express()
const savedir = path.join(process.cwd(), 'data')
const upload = multer({
	storage: multer.memoryStorage(),
	limits: {
		fileSize: 200000
	}
})
const blacklist = [
	'script',
	'noscript',
	'frame',
	'iframe',
	'object',
	'embed',
	'svg',
	'math',
	'base',
	'link',
	'style',
	'plaintext',
	'xmp',
	'portal',
	'source',
	'track',
	'video',
	'audio',
	'template[shadowrootmode]',
	'meta[http-equiv]'
]
const other = [
	'srcdoc',
	'ping',
	'background',
	'srcset'
]

let browser
const flag = (await fs.readFile('/flag', 'utf8')).trim()

app.disable('x-powered-by')
app.use(express.urlencoded({ extended: false }))

await fs.mkdir(savedir, { recursive: true })
browser = await chromium.launch({
	headless: true,
	args: ['--disable-dev-shm-usage']
})

function lines(parts) {
	return parts.join('\n')
}

function esc(value) {
	return value
		.replaceAll('&', '&amp;')
		.replaceAll('<', '&lt;')
		.replaceAll('>', '&gt;')
		.replaceAll('"', '&quot;')
}

function layout(title, body) {
	return lines([
		'<!doctype html>',
		'<html>',
		'<head>',
		'\t<meta charset="utf-8">',
		`\t<title>${title}</title>`,
		'</head>',
		'<body>',
		`\t<h1>${title}</h1>`,
		body,
		'</body>',
		'</html>'
	])
}

function homeview(id, text) {
	const postlink = id ? `<p><a href="/post/${id}">/post/${id}</a></p>` : ''
	const reportlink = id ? `<p><a href="/report?id=${id}">report</a></p>` : ''
	const body = text ? `<pre>${esc(text)}</pre>` : ''

	return layout(`byte512's blog 💚`, lines([
		'\t<form method="post" enctype="multipart/form-data">',
		'\t\t<input type="file" name="file" accept=".html,text/html" required>',
		'\t\t<button>publish</button>',
		'\t</form>',
		postlink ? `\t${postlink}` : '',
		reportlink ? `\t${reportlink}` : '',
		body ? `\t${body}` : ''
	].filter(Boolean)))
}

function reportview(id) {
	const value = id ? ` value="${id}"` : ''

	return layout(`byte512's blog`, lines([
		'\t<form method="post" action="/report">',
		`\t\t<input type="text" name="id" pattern="[a-f0-9]{16}" maxlength="16"${value} required>`,
		'\t\t<button>report</button>',
		'\t</form>',
		'\t<p><a href="/">back</a></p>'
	]))
}

function okid(id) {
	return /^[a-f0-9]{16}$/.test(id)
}

async function nextid() {
	for (;;) {
		const id = crypto.randomBytes(8).toString('hex')

		try {
			await fs.access(path.join(savedir, `${id}.html`))
		} catch {
			return id
		}
	}
}

async function loadfile(id) {
	try {
		return await fs.readFile(path.join(savedir, `${id}.html`))
	} catch {
		return null
	}
}

async function savefile(buf) {
	const id = await nextid()

	await fs.writeFile(path.join(savedir, `${id}.html`), buf)

	return id
}

async function checkfile(buf) {
	const view = await browser.newContext({
		javaScriptEnabled: false
	})
	const page = await view.newPage()

	await page.route('**/*', async route => {
		const url = route.request().url()

		if (url.startsWith('data:')) {
			await route.continue()
			return
		}

		await route.abort()
	})

	try {
		await page.goto(`data:text/html;base64,${buf.toString('base64')}`, {
			waitUntil: 'domcontentloaded',
			timeout: 10000
		})

		const state = await page.evaluate(args => {
			const { other, blacklist } = args
			const root = document.documentElement

			if (!root || root.tagName !== 'HTML') {
				return false
			}

			const badtag = document.querySelector(blacklist.join(','))

			if (badtag) {
				return false
			}

			for (const node of document.querySelectorAll('*')) {
				for (const name of node.getAttributeNames()) {
					const value = node.getAttribute(name) || ''

					if (name.startsWith('on')) {
						return false
					}

					if (other.includes(name)) {
						return false
					}

					if (/(^|[\s,])javascript:/i.test(value)) {
						return false
					}
				}
			}

			return true
		}, {
			other,
			blacklist
		})

		return state
	} catch {
		return false
	} finally {
		await view.close()
	}
}

function wait(ms) {
	return new Promise(resolve => setTimeout(resolve, ms))
}

app.get('/', async (req, res) => {
	const id = typeof req.query.id === 'string' && okid(req.query.id)
		? req.query.id
		: ''

	res.set('content-type', 'text/html; charset=utf-8')
	res.send(homeview(id, ''))
})

app.get('/report', async (req, res) => {
	const id = typeof req.query.id === 'string' && okid(req.query.id)
		? req.query.id
		: ''

	res.set('content-type', 'text/html; charset=utf-8')
	res.send(reportview(id))
})

app.post('/', upload.single('file'), async (req, res) => {
	if (!req.file || !req.file.buffer) {
		res.status(400).type('text/plain').send('nope')
		return
	}

	const pass = await checkfile(req.file.buffer)

	if (!pass) {
		res.status(400).type('text/plain').send('nope')
		return
	}

	const id = await savefile(req.file.buffer)

	res.redirect(`/?id=${id}`)
})

app.get('/post/:id', async (req, res) => {
	const id = req.params.id

	if (!okid(id)) {
		res.status(404).type('text/plain').send('nope')
		return
	}

	const buf = await loadfile(id)

	if (!buf) {
		res.status(404).type('text/plain').send('nope')
		return
	}

	const cut = Math.min(buf.length, 2048)

	res.statusCode = 200
	res.setHeader('content-type', 'text/html')
	res.setHeader('cache-control', 'no-store')
	res.flushHeaders()
	res.write(buf.subarray(0, cut))

	if (buf.length > cut) {
		await wait(1200)
		res.write(buf.subarray(cut))
	}

	res.end()
})

app.post('/report', async (req, res) => {
	const id = typeof req.body.id === 'string' ? req.body.id : ''

	if (!okid(id)) {
		res.status(404).type('text/plain').send('nope')
		return
	}

	const buf = await loadfile(id)

	if (!buf) {
		res.status(404).type('text/plain').send('nope')
		return
	}

	await visit(id, flag)
	res.type('text/plain').send('ok')
})

app.listen(3000, '0.0.0.0')
