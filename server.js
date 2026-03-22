require('dotenv').config();

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  Client,
  GatewayIntentBits,
  REST,
  Routes,
  SlashCommandBuilder,
  PermissionFlagsBits,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  ChannelType,
  EmbedBuilder,
  AttachmentBuilder,
} = require('discord.js');

const PORT = Number(process.env.PORT || 3000);
const HOST = '0.0.0.0';
const SESSION_TTL = 15 * 60 * 1000;

const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const DISCORD_TOKEN = process.env.DISCORD_TOKEN || '';
const CLIENT_ID = process.env.CLIENT_ID || '';
const GUILD_ID = process.env.GUILD_ID || '';
const ADMIN_ROLE = process.env.ADMIN_ROLE || '';

const SUPPORT_ROLE_ID = process.env.SUPPORT_ROLE_ID || '';
const TRANSCRIPT_CHANNEL_ID = process.env.TRANSCRIPT_CHANNEL_ID || '';
const MESSAGE_LOG_CHANNEL_ID = process.env.MESSAGE_LOG_CHANNEL_ID || '';
const STATUS_CHANNEL_ID = process.env.STATUS_CHANNEL_ID || '';
const TICKET_CATEGORY_ID =
  process.env.TICKET_CATEGORY_ID && process.env.TICKET_CATEGORY_ID !== 'optional'
    ? process.env.TICKET_CATEGORY_ID
    : null;

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const KEYS_FILE = process.env.KEYS_FILE || path.join(DATA_DIR, 'keys.json');

fs.mkdirSync(path.dirname(KEYS_FILE), { recursive: true });

function loadKeys() {
  try {
    if (!fs.existsSync(KEYS_FILE)) return {};
    return JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
  } catch (error) {
    console.error('[keys] Failed to load keys:', error.message);
    return {};
  }
}

function saveKeys(keys) {
  fs.mkdirSync(path.dirname(KEYS_FILE), { recursive: true });
  fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value).trim().toUpperCase()).digest('hex');
}

function newToken() {
  return crypto.randomBytes(32).toString('hex');
}

function genKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const segment = (length) =>
    Array.from({ length }, () => chars[crypto.randomInt(chars.length)]).join('');
  return `ZZZ-${segment(4)}-${segment(4)}-${segment(4)}`;
}

function addKey(keys, plaintext, opts = {}) {
  const key = String(plaintext).trim().toUpperCase();
  const hash = sha256(key);

  if (!key || keys[hash]) return null;

  keys[hash] = {
    plaintext: key,
    active: true,
    hwid: null,
    expires: opts.expires || null,
    discord: opts.discord || '',
    discordId: opts.discordId || '',
    note: opts.note || '',
    createdAt: Date.now(),
    lastSeen: null,
    sessionToken: null,
    sessionExp: null,
  };

  return hash;
}

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  });
  res.end(body);
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(body || '{}'));
      } catch (error) {
        reject(error);
      }
    });
    req.on('error', reject);
  });
}

function checkAdmin(req) {
  if (!ADMIN_TOKEN) return false;
  return (req.headers.authorization || '') === `Bearer ${ADMIN_TOKEN}`;
}

async function handleValidate(req, res) {
  let body;

  try {
    body = await parseBody(req);
  } catch {
    return sendJson(res, 400, { valid: false, error: 'Bad JSON.' });
  }

  const { key, hwid } = body;
  if (!key || !hwid) {
    return sendJson(res, 400, { valid: false, error: 'Missing key or hwid.' });
  }

  const keys = loadKeys();
  const hash = sha256(key);
  const entry = keys[hash];

  if (!entry) return sendJson(res, 200, { valid: false, error: 'Invalid key.' });
  if (!entry.active) return sendJson(res, 200, { valid: false, error: 'This key has been revoked.' });
  if (entry.expires && entry.expires < Date.now()) {
    return sendJson(res, 200, { valid: false, error: 'This key has expired.' });
  }
  if (entry.hwid && entry.hwid !== hwid) {
    return sendJson(res, 200, { valid: false, error: 'Key already activated on another device.' });
  }

  entry.hwid = hwid;
  entry.sessionToken = newToken();
  entry.sessionExp = Date.now() + SESSION_TTL;
  entry.lastSeen = Date.now();
  keys[hash] = entry;
  saveKeys(keys);

  return sendJson(res, 200, {
    valid: true,
    expires: entry.expires || null,
    discord: entry.discord || '',
    note: entry.note || '',
    sessionToken: entry.sessionToken,
    sessionExp: entry.sessionExp,
  });
}

async function handleCheckSession(req, res) {
  let body;

  try {
    body = await parseBody(req);
  } catch {
    return sendJson(res, 200, { valid: false });
  }

  const { sessionToken, hwid } = body;
  if (!sessionToken || !hwid) return sendJson(res, 200, { valid: false });

  const keys = loadKeys();
  const entry = Object.values(keys).find(
    (value) => value.sessionToken === sessionToken && value.hwid === hwid,
  );

  if (!entry || !entry.active) return sendJson(res, 200, { valid: false });
  if (entry.expires && entry.expires < Date.now()) return sendJson(res, 200, { valid: false });

  entry.sessionExp = Date.now() + SESSION_TTL;
  entry.lastSeen = Date.now();
  saveKeys(keys);

  return sendJson(res, 200, {
    valid: true,
    discord: entry.discord || '',
    sessionExp: entry.sessionExp,
  });
}

async function handleAdminList(req, res) {
  if (!checkAdmin(req)) return sendJson(res, 401, { error: 'Unauthorized.' });

  const keys = loadKeys();
  return sendJson(res, 200, {
    ok: true,
    keys: Object.entries(keys).map(([hash, entry]) => ({
      hash,
      key: entry.plaintext,
      active: entry.active,
      hwid: entry.hwid || null,
      expires: entry.expires || null,
      discord: entry.discord || '',
      note: entry.note || '',
      lastSeen: entry.lastSeen || null,
    })),
  });
}

async function handleAdminAdd(req, res) {
  if (!checkAdmin(req)) return sendJson(res, 401, { error: 'Unauthorized.' });

  let body;
  try {
    body = await parseBody(req);
  } catch {
    return sendJson(res, 400, { error: 'Bad JSON.' });
  }

  const keys = loadKeys();
  const hash = addKey(keys, body.key || genKey(), body);
  if (!hash) return sendJson(res, 409, { error: 'Key already exists.' });

  saveKeys(keys);
  return sendJson(res, 200, { ok: true, hash, key: keys[hash].plaintext });
}

async function handleAdminBulk(req, res) {
  if (!checkAdmin(req)) return sendJson(res, 401, { error: 'Unauthorized.' });

  let body;
  try {
    body = await parseBody(req);
  } catch {
    return sendJson(res, 400, { error: 'Bad JSON.' });
  }

  const keys = loadKeys();
  const added = (body.keys || []).filter((key) => addKey(keys, key, body));
  saveKeys(keys);

  return sendJson(res, 200, { ok: true, added: added.length, keys: added });
}

async function handleAdminRevoke(req, res) {
  if (!checkAdmin(req)) return sendJson(res, 401, { error: 'Unauthorized.' });

  let body;
  try {
    body = await parseBody(req);
  } catch {
    return sendJson(res, 400, { error: 'Bad JSON.' });
  }

  const keys = loadKeys();
  const hash = body.hash || sha256(body.key || '');
  if (!keys[hash]) return sendJson(res, 404, { error: 'Key not found.' });

  keys[hash].active = false;
  saveKeys(keys);
  return sendJson(res, 200, { ok: true });
}

async function handleAdminResetHwid(req, res) {
  if (!checkAdmin(req)) return sendJson(res, 401, { error: 'Unauthorized.' });

  let body;
  try {
    body = await parseBody(req);
  } catch {
    return sendJson(res, 400, { error: 'Bad JSON.' });
  }

  const keys = loadKeys();
  const hash = body.hash || sha256(body.key || '');
  if (!keys[hash]) return sendJson(res, 404, { error: 'Key not found.' });

  keys[hash].hwid = null;
  keys[hash].sessionToken = null;
  keys[hash].sessionExp = null;
  saveKeys(keys);

  return sendJson(res, 200, { ok: true });
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST,GET,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    });
    return res.end();
  }

  const url = req.url.split('?')[0];

  if (req.method === 'GET' && url === '/') {
    return sendJson(res, 200, {
      ok: true,
      service: 'discord-bot-key-server',
      botEnabled: Boolean(DISCORD_TOKEN && CLIENT_ID && GUILD_ID),
    });
  }

  if (req.method === 'GET' && url === '/ping') return sendJson(res, 200, { ok: true });
  if (req.method === 'GET' && url === '/healthz') return sendJson(res, 200, { ok: true });
  if (req.method === 'POST' && url === '/validate') return handleValidate(req, res);
  if (req.method === 'POST' && url === '/check-session') return handleCheckSession(req, res);
  if (req.method === 'GET' && url === '/admin/keys') return handleAdminList(req, res);
  if (req.method === 'POST' && url === '/admin/add') return handleAdminAdd(req, res);
  if (req.method === 'POST' && url === '/admin/bulk') return handleAdminBulk(req, res);
  if (req.method === 'POST' && url === '/admin/revoke') return handleAdminRevoke(req, res);
  if (req.method === 'POST' && url === '/admin/reset-hwid') return handleAdminResetHwid(req, res);

  return sendJson(res, 404, { error: 'Not found.' });
});

server.listen(PORT, HOST, () => {
  console.log(`[app] HTTP server listening on ${HOST}:${PORT}`);
  console.log(`[app] Keys file: ${KEYS_FILE}`);
});

if (!DISCORD_TOKEN || !CLIENT_ID || !GUILD_ID) {
  console.log('[bot] Discord bot disabled — set DISCORD_TOKEN, CLIENT_ID, and GUILD_ID.');
  process.exitCode = 0;
} else {
  const client = new Client({
    intents: [
      GatewayIntentBits.Guilds,
      GatewayIntentBits.GuildMessages,
      GatewayIntentBits.MessageContent,
      GatewayIntentBits.GuildMembers,
      GatewayIntentBits.GuildInvites,
    ],
  });

  const cachedInvites = new Map();

  const commands = [
    new SlashCommandBuilder()
      .setName('genkey')
      .setDescription('[Admin] Generate key(s) and optionally DM to a user')
      .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
      .addIntegerOption((option) =>
        option.setName('amount').setDescription('How many keys').setMinValue(1).setMaxValue(50),
      )
      .addUserOption((option) => option.setName('user').setDescription('DM key to this user'))
      .addStringOption((option) => option.setName('note').setDescription('Optional note')),

    new SlashCommandBuilder()
      .setName('revoke')
      .setDescription('[Admin] Revoke a key')
      .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
      .addStringOption((option) => option.setName('key').setDescription('Key to revoke').setRequired(true)),

    new SlashCommandBuilder()
      .setName('resethwid')
      .setDescription('[Admin] Reset HWID so key works on a new device')
      .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
      .addStringOption((option) => option.setName('key').setDescription('Key to reset').setRequired(true)),

    new SlashCommandBuilder()
      .setName('keyinfo')
      .setDescription('[Admin] Look up info on a key')
      .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
      .addStringOption((option) => option.setName('key').setDescription('Key to look up').setRequired(true)),

    new SlashCommandBuilder()
      .setName('keys')
      .setDescription('[Admin] List all keys')
      .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild),

    new SlashCommandBuilder().setName('mykey').setDescription('Get your key sent to your DMs'),
  ].map((command) => command.toJSON());

  function isAdmin(interaction) {
    if (ADMIN_ROLE) {
      return (
        interaction.member.roles.cache.has(ADMIN_ROLE) ||
        interaction.member.permissions.has(PermissionFlagsBits.ManageGuild)
      );
    }

    return interaction.member.permissions.has(PermissionFlagsBits.ManageGuild);
  }

  client.once('ready', async () => {
    console.log(`[bot] Logged in as ${client.user.tag}`);

    client.user.setPresence({
      status: 'dnd',
      activities: [{ name: 'bloodrain', type: 3 }],
    });

    for (const guild of client.guilds.cache.values()) {
      try {
        const invites = await guild.invites.fetch();
        invites.forEach((invite) => cachedInvites.set(invite.code, invite.uses));
      } catch (error) {
        console.warn(`[bot] Failed to cache invites for ${guild.name}: ${error.message}`);
      }
    }

    if (STATUS_CHANNEL_ID) {
      const statusChannel = await client.channels.fetch(STATUS_CHANNEL_ID).catch(() => null);
      if (statusChannel?.isTextBased()) {
        await statusChannel.setName('🟢-ticket-bot-online').catch(() => {});
      }
    }

    const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);
    try {
      await rest.put(Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID), { body: commands });
      console.log('[bot] Slash commands registered.');
    } catch (error) {
      console.error('[bot] Failed to register commands:', error.message);
    }
  });

  client.on('messageCreate', async (message) => {
    if (message.author.bot) return;

    if (
      message.content === '!ticket-panel' &&
      message.member.permissions.has(PermissionFlagsBits.Administrator)
    ) {
      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('open_ticket').setLabel('🩸 Open Ticket').setStyle(ButtonStyle.Danger),
      );

      await message.channel.send({
        content: 'Click the button below to create a ticket.',
        components: [row],
      });
    }
  });

  client.on('interactionCreate', async (interaction) => {
    if (interaction.isButton()) {
      if (interaction.customId === 'open_ticket') {
        const existing = interaction.guild.channels.cache.find(
          (channel) => channel.name === `ticket-${interaction.user.username.toLowerCase()}`,
        );

        if (existing) {
          return interaction.reply({
            content: `You already have a ticket: ${existing}`,
            ephemeral: true,
          });
        }

        const permissionOverwrites = [
          { id: interaction.guild.id, deny: [PermissionFlagsBits.ViewChannel] },
          {
            id: interaction.user.id,
            allow: [
              PermissionFlagsBits.ViewChannel,
              PermissionFlagsBits.SendMessages,
              PermissionFlagsBits.ReadMessageHistory,
            ],
          },
        ];

        if (SUPPORT_ROLE_ID) {
          permissionOverwrites.push({
            id: SUPPORT_ROLE_ID,
            allow: [
              PermissionFlagsBits.ViewChannel,
              PermissionFlagsBits.SendMessages,
              PermissionFlagsBits.ReadMessageHistory,
            ],
          });
        }

        const channel = await interaction.guild.channels.create({
          name: `ticket-${interaction.user.username}`,
          type: ChannelType.GuildText,
          parent: TICKET_CATEGORY_ID,
          permissionOverwrites,
        });

        const closeRow = new ActionRowBuilder().addComponents(
          new ButtonBuilder()
            .setCustomId('close_ticket')
            .setLabel('Close Ticket')
            .setStyle(ButtonStyle.Danger),
        );

        const supportMention = SUPPORT_ROLE_ID ? `\n<@&${SUPPORT_ROLE_ID}>` : '';
        await channel.send({
          content: `Hello ${interaction.user}! Seller will be with you shortly.${supportMention}`,
          components: [closeRow],
        });

        return interaction.reply({ content: `Your ticket: ${channel}`, ephemeral: true });
      }

      if (interaction.customId === 'close_ticket') {
        await interaction.reply({
          content: 'Saving transcript and closing in 5 seconds...',
          ephemeral: true,
        });

        const messages = await interaction.channel.messages.fetch({ limit: 100 });
        const sorted = messages.sort((a, b) => a.createdTimestamp - b.createdTimestamp);
        const transcript = sorted
          .map(
            (message) =>
              `[${new Date(message.createdTimestamp).toLocaleString()}] ${message.author.tag}: ${
                message.content
              }`,
          )
          .join('\n');

        if (TRANSCRIPT_CHANNEL_ID) {
          const logChannel = await interaction.guild.channels
            .fetch(TRANSCRIPT_CHANNEL_ID)
            .catch(() => null);
          if (logChannel?.isTextBased()) {
            const buffer = Buffer.from(transcript, 'utf8');
            const attachment = new AttachmentBuilder(buffer, {
              name: `${interaction.channel.name}.txt`,
            });
            await logChannel.send({
              content: `📜 Transcript for **${interaction.channel.name}**`,
              files: [attachment],
            });
          }
        }

        setTimeout(() => {
          interaction.channel.delete().catch(() => {});
        }, 5000);
      }

      return;
    }

    if (!interaction.isChatInputCommand()) return;

    const commandName = interaction.commandName;

    if (commandName === 'genkey') {
      if (!isAdmin(interaction)) {
        return interaction.reply({ content: '❌ No permission.', ephemeral: true });
      }

      await interaction.deferReply({ ephemeral: true });

      const amount = interaction.options.getInteger('amount') || 1;
      const target = interaction.options.getUser('user');
      const note = interaction.options.getString('note') || '';
      const keys = loadKeys();
      const generatedKeys = [];

      for (let index = 0; index < amount; index += 1) {
        const key = genKey();
        addKey(keys, key, {
          discord: target ? target.tag : '',
          discordId: target ? target.id : '',
          note,
        });
        generatedKeys.push(key);
      }

      saveKeys(keys);

      const keyList = generatedKeys.map((key) => `\`${key}\``).join('\n');

      if (target && amount === 1) {
        try {
          await target.send(
            `## Your key\n\`\`\`\n${generatedKeys[0]}\n\`\`\`\nActivate it in the extension. Keep this private!`,
          );
          return interaction.editReply(`✅ Key generated and DMed to **${target.tag}**.\n${keyList}`);
        } catch {
          return interaction.editReply(`✅ Generated, but I couldn't DM the user.\n${keyList}`);
        }
      }

      return interaction.editReply(
        `✅ Generated **${amount}** key${amount > 1 ? 's' : ''}:\n${keyList}`,
      );
    }

    if (commandName === 'revoke') {
      if (!isAdmin(interaction)) {
        return interaction.reply({ content: '❌ No permission.', ephemeral: true });
      }

      const key = interaction.options.getString('key').trim().toUpperCase();
      const keys = loadKeys();
      const hash = sha256(key);

      if (!keys[hash]) {
        return interaction.reply({ content: '❌ Key not found.', ephemeral: true });
      }

      keys[hash].active = false;
      saveKeys(keys);
      return interaction.reply({ content: `✅ \`${key}\` revoked.`, ephemeral: true });
    }

    if (commandName === 'resethwid') {
      if (!isAdmin(interaction)) {
        return interaction.reply({ content: '❌ No permission.', ephemeral: true });
      }

      const key = interaction.options.getString('key').trim().toUpperCase();
      const keys = loadKeys();
      const hash = sha256(key);

      if (!keys[hash]) {
        return interaction.reply({ content: '❌ Key not found.', ephemeral: true });
      }

      keys[hash].hwid = null;
      keys[hash].sessionToken = null;
      keys[hash].sessionExp = null;
      saveKeys(keys);

      return interaction.reply({ content: `✅ HWID reset for \`${key}\`.`, ephemeral: true });
    }

    if (commandName === 'keyinfo') {
      if (!isAdmin(interaction)) {
        return interaction.reply({ content: '❌ No permission.', ephemeral: true });
      }

      const key = interaction.options.getString('key').trim().toUpperCase();
      const keys = loadKeys();
      const entry = keys[sha256(key)];

      if (!entry) {
        return interaction.reply({ content: '❌ Key not found.', ephemeral: true });
      }

      return interaction.reply({
        embeds: [
          {
            title: '🔑 Key Info',
            color: entry.active ? 0x22c55e : 0xef4444,
            fields: [
              { name: 'Key', value: `\`${entry.plaintext}\``, inline: false },
              { name: 'Status', value: entry.active ? '✅ Active' : '❌ Revoked', inline: true },
              {
                name: 'Expires',
                value: entry.expires ? `<t:${Math.floor(entry.expires / 1000)}:R>` : 'Lifetime',
                inline: true,
              },
              {
                name: 'HWID',
                value: entry.hwid ? `\`${entry.hwid.slice(0, 8)}…\`` : 'Unbound',
                inline: true,
              },
              { name: 'Discord', value: entry.discord || 'None', inline: true },
              { name: 'Note', value: entry.note || 'None', inline: true },
              {
                name: 'Last Seen',
                value: entry.lastSeen ? `<t:${Math.floor(entry.lastSeen / 1000)}:R>` : 'Never',
                inline: true,
              },
            ],
          },
        ],
        ephemeral: true,
      });
    }

    if (commandName === 'keys') {
      if (!isAdmin(interaction)) {
        return interaction.reply({ content: '❌ No permission.', ephemeral: true });
      }

      const keys = loadKeys();
      const all = Object.values(keys);
      const lines = all
        .slice(0, 25)
        .map(
          (entry) =>
            `${entry.active ? '✅' : '❌'}${entry.hwid ? '🔒' : '🔓'} \`${entry.plaintext}\`${
              entry.discord ? ` — ${entry.discord}` : ''
            }${entry.note ? ` (${entry.note})` : ''}`,
        )
        .join('\n');

      return interaction.reply({
        embeds: [
          {
            title: '🔑 Keys',
            description: lines || 'No keys yet.',
            color: 0xa855f7,
            footer: {
              text: `Total: ${all.length} | Active: ${all.filter((entry) => entry.active).length} | Bound: ${all.filter((entry) => entry.hwid).length}${all.length > 25 ? ' | Showing first 25' : ''}`,
            },
          },
        ],
        ephemeral: true,
      });
    }

    if (commandName === 'mykey') {
      await interaction.deferReply({ ephemeral: true });
      const keys = loadKeys();
      const entry = Object.values(keys).find(
        (value) => value.discordId === interaction.user.id && value.active,
      );

      if (!entry) {
        return interaction.editReply(
          '❌ No active key found for your account. Ask an admin to generate one with `/genkey @you`.',
        );
      }

      try {
        await interaction.user.send(
          `## Your key\n\`\`\`\n${entry.plaintext}\n\`\`\`\nActivate it in the extension. Keep this private!`,
        );
        return interaction.editReply('✅ Key sent to your DMs!');
      } catch {
        return interaction.editReply(`✅ Your key: \`${entry.plaintext}\``);
      }
    }
  });

  client.on('messageDelete', async (message) => {
    if (message.author?.bot || !MESSAGE_LOG_CHANNEL_ID) return;

    const logChannel = await message.guild?.channels.fetch(MESSAGE_LOG_CHANNEL_ID).catch(() => null);
    if (!logChannel?.isTextBased()) return;

    const embed = new EmbedBuilder()
      .setColor(0xff0000)
      .setTitle('🗑️ Message Deleted')
      .addFields(
        { name: 'Author', value: `${message.author.tag} (${message.author.id})`, inline: true },
        { name: 'Channel', value: `${message.channel}`, inline: true },
        { name: 'Content', value: message.content || '*empty*' },
      )
      .setTimestamp();

    await logChannel.send({ embeds: [embed] }).catch(() => {});
  });

  client.on('messageUpdate', async (oldMessage, newMessage) => {
    if (oldMessage.author?.bot || oldMessage.content === newMessage.content || !MESSAGE_LOG_CHANNEL_ID) {
      return;
    }

    const logChannel = await oldMessage.guild?.channels.fetch(MESSAGE_LOG_CHANNEL_ID).catch(() => null);
    if (!logChannel?.isTextBased()) return;

    const embed = new EmbedBuilder()
      .setColor(0xffa500)
      .setTitle('✏️ Message Edited')
      .addFields(
        { name: 'Author', value: `${oldMessage.author.tag} (${oldMessage.author.id})`, inline: true },
        { name: 'Channel', value: `${oldMessage.channel}`, inline: true },
        { name: 'Before', value: oldMessage.content || '*empty*' },
        { name: 'After', value: newMessage.content || '*empty*' },
      )
      .setTimestamp();

    await logChannel.send({ embeds: [embed] }).catch(() => {});
  });

  client.on('guildMemberAdd', async (member) => {
    if (!MESSAGE_LOG_CHANNEL_ID) return;

    const logChannel = await member.guild.channels.fetch(MESSAGE_LOG_CHANNEL_ID).catch(() => null);
    if (!logChannel?.isTextBased()) return;

    let inviter = 'Unknown';

    try {
      const invites = await member.guild.invites.fetch();
      const usedInvite = invites.find((invite) => invite.uses > (cachedInvites.get(invite.code) || 0));
      if (usedInvite?.inviter) inviter = `<@${usedInvite.inviter.id}>`;
      invites.forEach((invite) => cachedInvites.set(invite.code, invite.uses));
    } catch {}

    const embed = new EmbedBuilder()
      .setColor(0x00ff00)
      .setTitle('📥 Member Joined')
      .addFields(
        { name: 'Member', value: `${member.user.tag} (${member.id})`, inline: true },
        { name: 'Invited by', value: inviter, inline: true },
      )
      .setTimestamp();

    await logChannel.send({ embeds: [embed] }).catch(() => {});
  });

  client.on('guildMemberRemove', async (member) => {
    if (!MESSAGE_LOG_CHANNEL_ID) return;

    const logChannel = await member.guild.channels.fetch(MESSAGE_LOG_CHANNEL_ID).catch(() => null);
    if (!logChannel?.isTextBased()) return;

    const embed = new EmbedBuilder()
      .setColor(0xff0000)
      .setTitle('📤 Member Left')
      .addFields({ name: 'Member', value: `${member.user.tag} (${member.id})`, inline: true })
      .setTimestamp();

    await logChannel.send({ embeds: [embed] }).catch(() => {});
  });

  async function markOfflineAndExit(signal) {
    console.log(`[app] Received ${signal}, shutting down.`);

    if (STATUS_CHANNEL_ID) {
      const statusChannel = await client.channels.fetch(STATUS_CHANNEL_ID).catch(() => null);
      if (statusChannel?.isTextBased()) {
        await statusChannel.setName('🔴-ticket-bot-offline').catch(() => {});
      }
    }

    await client.destroy();
    process.exit(0);
  }

  process.on('SIGINT', () => {
    markOfflineAndExit('SIGINT').catch(() => process.exit(0));
  });

  process.on('SIGTERM', () => {
    markOfflineAndExit('SIGTERM').catch(() => process.exit(0));
  });

  client.login(DISCORD_TOKEN).catch((error) => {
    console.error('[bot] Discord login failed:', error.message);
  });
}
