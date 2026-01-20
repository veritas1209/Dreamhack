local var_0_0
local var_0_1, var_0_2 = pcall(require, "bit")

if var_0_1 then
	var_0_0 = var_0_2
elseif bit32 then
	var_0_0 = bit32
else
	var_0_0 = {
		bxor = function(arg_1_0, arg_1_1)
			local var_1_0 = 0
			local var_1_1 = 1

			while arg_1_0 > 0 or arg_1_1 > 0 do
				if arg_1_0 % 2 ~= arg_1_1 % 2 then
					var_1_0 = var_1_0 + var_1_1
				end

				arg_1_0 = math.floor(arg_1_0 / 2)
				arg_1_1 = math.floor(arg_1_1 / 2)
				var_1_1 = var_1_1 * 2
			end

			return var_1_0
		end,
		lshift = function(arg_2_0, arg_2_1)
			return arg_2_0 * 2^arg_2_1 % 4294967296
		end,
		rshift = function(arg_3_0, arg_3_1)
			return math.floor(arg_3_0 % 4294967296 / 2^arg_3_1)
		end,
		band = function(arg_4_0, arg_4_1)
			local var_4_0 = 0
			local var_4_1 = 1

			while arg_4_0 > 0 or arg_4_1 > 0 do
				local var_4_2 = arg_4_0 % 2
				local var_4_3 = arg_4_1 % 2

				if var_4_2 == 1 and var_4_3 == 1 then
					var_4_0 = var_4_0 + var_4_1
				end

				arg_4_0 = math.floor(arg_4_0 / 2)
				arg_4_1 = math.floor(arg_4_1 / 2)
				var_4_1 = var_4_1 * 2
			end

			return var_4_0
		end
	}
end

local function var_0_3(arg_5_0, arg_5_1, arg_5_2)
	if arg_5_0 < arg_5_1 then
		return arg_5_1
	end

	if arg_5_2 < arg_5_0 then
		return arg_5_2
	end

	return arg_5_0
end

local function var_0_4(arg_6_0, arg_6_1, arg_6_2, arg_6_3, arg_6_4, arg_6_5, arg_6_6)
	love.graphics.rectangle(arg_6_0, arg_6_1, arg_6_2, arg_6_3, arg_6_4, arg_6_5 or 20, arg_6_6 or 20)
end

local function var_0_5(arg_7_0)
	if arg_7_0 < 0 then
		arg_7_0 = 0
	end

	arg_7_0 = math.floor(arg_7_0 + 1e-06)

	local var_7_0 = tostring(arg_7_0)
	local var_7_1 = {}
	local var_7_2 = 0

	for iter_7_0 = #var_7_0, 1, -1 do
		var_7_2 = var_7_2 + 1
		var_7_1[#var_7_1 + 1] = var_7_0:sub(iter_7_0, iter_7_0)

		if var_7_2 % 3 == 0 and iter_7_0 ~= 1 then
			var_7_1[#var_7_1 + 1] = ","
		end
	end

	local var_7_3 = {}

	for iter_7_1 = #var_7_1, 1, -1 do
		var_7_3[#var_7_3 + 1] = var_7_1[iter_7_1]
	end

	return table.concat(var_7_3)
end

local function var_0_6(arg_8_0)
	if love.filesystem.getInfo(arg_8_0) then
		local var_8_0, var_8_1 = pcall(love.graphics.newImage, arg_8_0)

		if var_8_0 then
			return var_8_1
		end
	end

	return nil
end

local function var_0_7()
	local var_9_0 = {
		"assets/NanumGothic.ttf",
		"assets/NanumGothicBold.ttf",
		"assets/NotoSansKR-Regular.otf",
		"assets/NotoSansKR-Medium.otf",
		"assets/font.ttf",
		"assets/font.otf"
	}

	for iter_9_0, iter_9_1 in ipairs(var_9_0) do
		if love.filesystem.getInfo(iter_9_1) then
			return iter_9_1
		end
	end

	return nil
end

local var_0_8 = 4294967296
local var_0_9 = 1664525
local var_0_10 = 1013904223

local function var_0_11(arg_10_0)
	return (var_0_9 * arg_10_0 + var_0_10) % var_0_8
end

local var_0_12 = var_0_0.tobit ~= nil

local function var_0_13(arg_11_0)
	arg_11_0 = arg_11_0 % var_0_8

	if var_0_12 then
		return var_0_0.tobit(arg_11_0)
	end

	return arg_11_0
end

local function var_0_14(arg_12_0)
	arg_12_0 = var_0_13(arg_12_0)
	arg_12_0 = var_0_13(var_0_0.bxor(arg_12_0, var_0_0.lshift(arg_12_0, 13)))
	arg_12_0 = var_0_13(var_0_0.bxor(arg_12_0, var_0_0.rshift(arg_12_0, 17)))
	arg_12_0 = var_0_13(var_0_0.bxor(arg_12_0, var_0_0.lshift(arg_12_0, 5)))

	return arg_12_0
end

local var_0_15 = 2654435769

local function var_0_16(arg_13_0, arg_13_1)
	local var_13_0 = (arg_13_0 + arg_13_1 * var_0_15) % var_0_8
	local var_13_1 = var_0_14(var_13_0)

	return var_0_0.band(var_13_1, 255)
end

local var_0_17 = {
	184,
	69,
	54,
	45,
	52,
	184,
	115,
	85,
	48,
	100,
	163,
	125,
	5,
	121,
	204,
	89,
	140,
	159,
	43,
	143,
	56,
	205,
	142,
	25,
	219,
	89,
	179,
	87,
	74,
	72,
	149,
	44,
	148,
	180,
	11,
	178,
	124,
	173,
	183,
	83,
	62,
	96
}

local function var_0_18(arg_14_0)
	local var_14_0 = {}

	for iter_14_0 = 1, #var_0_17 do
		local var_14_1 = var_0_17[iter_14_0]
		local var_14_2 = var_0_16(arg_14_0, iter_14_0)

		var_14_0[iter_14_0] = string.char(var_0_0.bxor(var_14_1, var_14_2))
	end

	return table.concat(var_14_0)
end

local function var_0_19(arg_15_0)
	local var_15_0 = "DH{"

	return type(arg_15_0) == "string" and #arg_15_0 >= #var_15_0 + 1 and arg_15_0:sub(1, #var_15_0) == var_15_0 and arg_15_0:sub(-1) == "}"
end

local var_0_20 = 540
local var_0_21 = 960
local var_0_22 = 999999999999
local var_0_23 = {
	bg = {
		1,
		1,
		1,
		1
	},
	text = {
		0.18,
		0.18,
		0.22,
		1
	},
	sub = {
		0.18,
		0.18,
		0.22,
		0.65
	},
	card = {
		1,
		1,
		1,
		0.88
	},
	line = {
		1,
		1,
		1,
		0.7
	},
	shadow = {
		0.08,
		0.08,
		0.12,
		0.14
	},
	dim = {
		0.04,
		0.04,
		0.06,
		0.55
	},
	pink = {
		1,
		0.74,
		0.84,
		1
	},
	mint = {
		0.72,
		0.94,
		0.86,
		1
	},
	lav = {
		0.84,
		0.82,
		0.98,
		1
	},
	sky = {
		0.78,
		0.9,
		1,
		1
	}
}
local var_0_24 = {
	med = nil,
	small = nil,
	huge = nil,
	big = nil
}
local var_0_25 = {
	bored = nil,
	ok = nil,
	hungry = nil,
	happy = nil
}
local var_0_26 = {
	key = 0,
	count = 0,
	bobT = 0,
	popupText = "",
	unlocked = false
}

local function var_0_27()
	love.graphics.setColor(var_0_23.bg)
	love.graphics.rectangle("fill", 0, 0, var_0_20, var_0_21)
end

local function var_0_28(arg_17_0, arg_17_1, arg_17_2, arg_17_3)
	love.graphics.setColor(var_0_23.shadow)
	var_0_4("fill", arg_17_0 + 3, arg_17_1 + 5, arg_17_2, arg_17_3, 22, 22)
	love.graphics.setColor(var_0_23.card)
	var_0_4("fill", arg_17_0, arg_17_1, arg_17_2, arg_17_3, 22, 22)
	love.graphics.setColor(var_0_23.line)
	var_0_4("line", arg_17_0, arg_17_1, arg_17_2, arg_17_3, 22, 22)
end

local function var_0_29()
	local var_18_0 = var_0_26.count % 40

	if var_0_26.unlocked and var_0_25.happy then
		return var_0_25.happy
	end

	if var_18_0 < 10 and var_0_25.ok then
		return var_0_25.ok
	end

	if var_18_0 < 20 and var_0_25.bored then
		return var_0_25.bored
	end

	if var_18_0 < 30 and var_0_25.hungry then
		return var_0_25.hungry
	end

	return var_0_25.ok or var_0_25.happy or var_0_25.bored or var_0_25.hungry
end

local function var_0_30()
	local var_19_0 = var_0_29()
	local var_19_1 = var_0_20 / 2
	local var_19_2 = 295
	local var_19_3 = math.sin(var_0_26.bobT * 2) * 6

	if var_19_0 then
		local var_19_4 = var_19_0:getWidth()
		local var_19_5 = var_19_0:getHeight()
		local var_19_6 = 270 / math.max(var_19_4, var_19_5)

		love.graphics.setColor(var_0_23.shadow)
		love.graphics.ellipse("fill", var_19_1, var_19_2 + 235, 190, 34)
		love.graphics.setColor(1, 1, 1, 1)
		love.graphics.draw(var_19_0, var_19_1, var_19_2 + var_19_3, 0, var_19_6, var_19_6, var_19_4 / 2, var_19_5 / 2)
	else
		love.graphics.setColor(var_0_23.shadow)
		love.graphics.ellipse("fill", var_19_1, var_19_2 + 235, 190, 34)
		love.graphics.setColor(var_0_23.pink)
		love.graphics.circle("fill", var_19_1, var_19_2 + var_19_3, 130)
	end
end

local function var_0_31()
	local var_20_0 = var_0_20 - 64
	local var_20_1 = 250
	local var_20_2 = 32
	local var_20_3 = 530

	var_0_28(var_20_2, var_20_3, var_20_0, var_20_1)
	love.graphics.setColor(var_0_23.text)
	love.graphics.setFont(var_0_24.huge)
	love.graphics.printf(var_0_5(var_0_26.count), var_20_2, var_20_3 + 90, var_20_0, "center")
	love.graphics.setFont(var_0_24.small)
	love.graphics.setColor(var_0_23.sub)
	love.graphics.printf("ESC = 종료 / R = 리셋", var_20_2, var_20_3 + 226, var_20_0, "center")
end

local function var_0_32()
	if not var_0_26.unlocked then
		return
	end

	love.graphics.setColor(var_0_23.dim)
	love.graphics.rectangle("fill", 0, 0, var_0_20, var_0_21)

	local var_21_0 = var_0_20 - 80
	local var_21_1 = 230
	local var_21_2 = 40
	local var_21_3 = (var_0_21 - var_21_1) / 2

	var_0_28(var_21_2, var_21_3, var_21_0, var_21_1)
	love.graphics.setColor(var_0_23.text)
	love.graphics.setFont(var_0_24.big)
	love.graphics.printf("플래그 획득!", var_21_2, var_21_3 + 26, var_21_0, "center")
	love.graphics.setFont(var_0_24.med)
	love.graphics.printf(var_0_26.popupText, var_21_2 + 18, var_21_3 + 108, var_21_0 - 36, "center")
	love.graphics.setFont(var_0_24.small)
	love.graphics.setColor(var_0_23.sub)
	love.graphics.printf("클릭하면 닫기", var_21_2, var_21_3 + var_21_1 - 34, var_21_0, "center")
end

local function var_0_33()
	if var_0_26.unlocked then
		return
	end

	if var_0_26.count ~= var_0_22 then
		return
	end

	local var_22_0 = var_0_18(var_0_26.key)

	if var_0_19(var_22_0) then
		var_0_26.unlocked = true
		var_0_26.popupText = var_22_0
	end
end

local function var_0_34()
	if var_0_26.unlocked then
		return
	end

	var_0_26.count = var_0_26.count + 1
	var_0_26.key = var_0_11(var_0_26.key)

	var_0_33()
end

function love.load()
	love.window.setTitle("아모의 놀이터")
	love.window.setIcon(love.image.newImageData("assets/mushroom.png"))
	love.window.setMode(var_0_20, var_0_21, {
		vsync = true,
		resizable = false
	})
	love.graphics.setBackgroundColor(var_0_23.bg)

	local var_24_0 = var_0_7()

	if var_24_0 then
		var_0_24.small = love.graphics.newFont(var_24_0, 16)
		var_0_24.med = love.graphics.newFont(var_24_0, 22)
		var_0_24.big = love.graphics.newFont(var_24_0, 34)
		var_0_24.huge = love.graphics.newFont(var_24_0, 56)
	else
		var_0_24.small = love.graphics.newFont(16)
		var_0_24.med = love.graphics.newFont(22)
		var_0_24.big = love.graphics.newFont(34)
		var_0_24.huge = love.graphics.newFont(56)
	end

	var_0_25.ok = var_0_6("assets/dreamy_ok.png")
	var_0_25.hungry = var_0_6("assets/dreamy_hungry.png")
	var_0_25.bored = var_0_6("assets/dreamy_bored.png")
	var_0_25.happy = var_0_6("assets/dreamy_happy.png")
	var_0_26.key = 3237998146
end

function love.update(arg_25_0)
	var_0_26.bobT = var_0_26.bobT + arg_25_0
end

function love.draw()
	var_0_27()
	var_0_30()
	var_0_31()
	var_0_32()
end

function love.mousepressed(arg_27_0, arg_27_1, arg_27_2)
	if arg_27_2 ~= 1 then
		return
	end

	if var_0_26.unlocked then
		var_0_26.unlocked = false

		return
	end

	var_0_34()
end

function love.keypressed(arg_28_0)
	if arg_28_0 == "escape" then
		love.event.quit()

		return
	end

	if var_0_26.unlocked then
		var_0_26.unlocked = false

		return
	end

	if arg_28_0 == "space" or arg_28_0 == "return" then
		var_0_34()

		return
	end

	if arg_28_0 == "r" then
		var_0_26.count = 0
		var_0_26.key = 3237998146
		var_0_26.unlocked = false
		var_0_26.popupText = ""

		return
	end
end
