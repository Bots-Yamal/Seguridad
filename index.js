
const {
  Client,
  GatewayIntentBits,
  Partials,
  ActivityType,
  EmbedBuilder,
  PermissionsBitField,
  REST,
  Routes,
  SlashCommandBuilder,
  ChannelType,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  AuditLogEvent
} = require("discord.js");

const fs = require("fs");
const path = require("path");

// ======================================
// SENTINEL SECURITY V2
// ======================================

const TOKEN = process.env.DISCORD_TOKEN;
const CLIENT_ID = process.env.CLIENT_ID;
const PREFIX = ".";

if (!TOKEN || !CLIENT_ID) {
  console.error("Faltan DISCORD_TOKEN o CLIENT_ID.");
  process.exit(1);
}

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildModeration,
    GatewayIntentBits.GuildWebhooks
  ],
  partials: [
    Partials.Message,
    Partials.Channel,
    Partials.GuildMember,
    Partials.User
  ]
});

const FILE = path.join(__dirname, "data.json");

const defaultServer = () => ({
  language: "es",
  logs: null,
  welcome: null,
  goodbye: null,
  autorole: null,

  ticketCategory: null,
  ticketSupportRole: null,
  ticketLogs: null,
  tickets: {},

  warnings: {},
  notes: {},
  cases: [],
  whitelist: [],

  security: {
    antiRaid: false,
    antiNuke: false,
    antiSpam: false,
    antiFlood: false,
    antiMentions: false,
    antiPhishing: false,
    antiWebhook: false,
    antiBot: false,
    antiPermission: false,
    lockdown: false
  },

  counters: {
    joins: [],
    messages: {},
    mentions: {},
    actions: {}
  }
});

// ======================================
// DATA
// ======================================

function loadData() {
  try {
    if (!fs.existsSync(FILE)) {
      fs.writeFileSync(FILE, JSON.stringify({ servers: {} }, null, 2));
    }

    const parsed = JSON.parse(fs.readFileSync(FILE, "utf8"));

    if (!parsed.servers || typeof parsed.servers !== "object") {
      parsed.servers = {};
    }

    return parsed;
  } catch (error) {
    console.error("Error leyendo data.json:", error);
    return { servers: {} };
  }
}

let data = loadData();

function saveData() {
  try {
    const temporary = `${FILE}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify(data, null, 2));
    fs.renameSync(temporary, FILE);
  } catch (error) {
    console.error("Error guardando data.json:", error);
  }
}

function getServer(guildId) {
  if (!data.servers[guildId]) {
    data.servers[guildId] = defaultServer();
  }

  const config = data.servers[guildId];
  const defaults = defaultServer();

  for (const [key, value] of Object.entries(defaults)) {
    if (config[key] === undefined) {
      config[key] = structuredClone(value);
    }
  }

  for (const [key, value] of Object.entries(defaults.security)) {
    if (config.security[key] === undefined) {
      config.security[key] = value;
    }
  }

  if (!config.tickets || typeof config.tickets !== "object") {
    config.tickets = {};
  }

  saveData();
  return config;
}

// ======================================
// EMBEDS AND RESPONSES
// ======================================

function timestamp() {
  return `<t:${Math.floor(Date.now() / 1000)}:F>`;
}

function makeEmbed(title, description, color = 0x1677FF) {
  return new EmbedBuilder()
    .setColor(color)
    .setTitle(`🛡️ ${title}`)
    .setDescription(description || "Sin información.")
    .addFields({
      name: "Fecha y hora",
      value: timestamp()
    })
    .setFooter({ text: "Sentinel Security" })
    .setTimestamp();
}

async function reply(ctx, message, color = 0x1677FF) {
  const e = makeEmbed("Sentinel Security", message, color);

  if (ctx.isChatInputCommand?.() || ctx.isButton?.()) {
    if (ctx.deferred && !ctx.replied) {
      return ctx.editReply({ embeds: [e] });
    }

    if (ctx.replied || ctx.deferred) {
      return ctx.followUp({ embeds: [e], ephemeral: true });
    }

    return ctx.reply({ embeds: [e], ephemeral: true });
  }

  return ctx.reply({ embeds: [e] });
}

async function log(guild, title, description, color = 0x1677FF) {
  try {
    const config = getServer(guild.id);
    if (!config.logs) return;

    const channel = guild.channels.cache.get(config.logs);
    if (!channel?.isTextBased()) return;

    await channel.send({
      embeds: [makeEmbed(title, description, color)]
    });
  } catch (error) {
    console.error("Error enviando log:", error);
  }
}

async function ticketLog(guild, title, description) {
  const config = getServer(guild.id);
  const channelId = config.ticketLogs || config.logs;
  if (!channelId) return;

  const channel = guild.channels.cache.get(channelId);
  if (!channel?.isTextBased()) return;

  await channel.send({
    embeds: [makeEmbed(title, description)]
  }).catch(() => {});
}

// ======================================
// PERMISSIONS
// ======================================

function hasPermission(member, permission) {
  return member?.permissions?.has(permission) ?? false;
}

function isWhitelisted(guildId, userId) {
  return getServer(guildId).whitelist.includes(userId);
}

function canManageTarget(actor, target) {
  if (!actor || !target) return false;
  if (actor.id === target.id) return false;
  if (target.id === actor.guild.ownerId) return false;
  if (actor.id === actor.guild.ownerId) return true;

  return actor.roles.highest.comparePositionTo(target.roles.highest) > 0;
}

async function getBotMember(guild) {
  return guild.members.me ||
    await guild.members.fetch(client.user.id).catch(() => null);
}

async function botHas(guild, permission, channel = null) {
  const me = await getBotMember(guild);
  if (!me) return false;

  return channel
    ? me.permissionsIn(channel).has(permission)
    : me.permissions.has(permission);
}

async function requireBotPermission(ctx, permission, channel = null) {
  if (!await botHas(ctx.guild, permission, channel)) {
    await reply(ctx, `Me falta el permiso **${permission}**.`, 0xE74C3C);
    return false;
  }

  return true;
}

async function requireUserPermission(ctx, permission) {
  const member = ctx.member;

  if (!hasPermission(member, permission)) {
    await reply(ctx, "No tenés permiso para ejecutar esta acción.", 0xE74C3C);
    return false;
  }

  return true;
}

async function getMember(guild, input) {
  if (!input) return null;

  const id = String(input).replace(/[<@!>]/g, "");
  if (!/^\d{17,20}$/.test(id)) return null;

  return guild.members.fetch(id).catch(() => null);
}

// ======================================
// MODERATION HISTORY
// ======================================

function addCase(guildId, entry) {
  const config = getServer(guildId);

  config.cases.push({
    id: Date.now(),
    ...entry,
    date: new Date().toISOString()
  });

  if (config.cases.length > 500) {
    config.cases.shift();
  }

  saveData();
}

// ======================================
// SLASH COMMANDS
// ======================================

const commands = [
  new SlashCommandBuilder()
    .setName("help")
    .setDescription("Ver todos los comandos de Sentinel Security"),

  new SlashCommandBuilder()
    .setName("ping")
    .setDescription("Ver la latencia del bot"),

  new SlashCommandBuilder()
    .setName("uptime")
    .setDescription("Ver el tiempo activo del bot"),

  new SlashCommandBuilder()
    .setName("botinfo")
    .setDescription("Información del bot"),

  new SlashCommandBuilder()
    .setName("serverinfo")
    .setDescription("Información del servidor"),

  new SlashCommandBuilder()
    .setName("userinfo")
    .setDescription("Información de un usuario")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario")),

  new SlashCommandBuilder()
    .setName("avatar")
    .setDescription("Ver avatar de un usuario")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario")),

  new SlashCommandBuilder()
    .setName("ban")
    .setDescription("Banear un usuario")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true))
    .addStringOption(o => o.setName("motivo").setDescription("Motivo")),

  new SlashCommandBuilder()
    .setName("unban")
    .setDescription("Desbanear por ID")
    .addStringOption(o => o.setName("id").setDescription("ID del usuario").setRequired(true)),

  new SlashCommandBuilder()
    .setName("kick")
    .setDescription("Expulsar un usuario")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true))
    .addStringOption(o => o.setName("motivo").setDescription("Motivo")),

  new SlashCommandBuilder()
    .setName("timeout")
    .setDescription("Aplicar timeout")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true))
    .addIntegerOption(o => o.setName("minutos").setDescription("Duración").setRequired(true).setMinValue(1).setMaxValue(40320))
    .addStringOption(o => o.setName("motivo").setDescription("Motivo")),

  new SlashCommandBuilder()
    .setName("untimeout")
    .setDescription("Quitar timeout")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true)),

  new SlashCommandBuilder()
    .setName("warn")
    .setDescription("Advertir a un usuario")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true))
    .addStringOption(o => o.setName("motivo").setDescription("Motivo").setRequired(true)),

  new SlashCommandBuilder()
    .setName("unwarn")
    .setDescription("Quitar una advertencia")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true))
    .addIntegerOption(o => o.setName("numero").setDescription("Número").setRequired(true).setMinValue(1)),

  new SlashCommandBuilder()
    .setName("warnings")
    .setDescription("Ver advertencias")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true)),

  new SlashCommandBuilder()
    .setName("purge")
    .setDescription("Eliminar mensajes")
    .addIntegerOption(o => o.setName("cantidad").setDescription("Cantidad").setRequired(true).setMinValue(1).setMaxValue(100)),

  new SlashCommandBuilder()
    .setName("slowmode")
    .setDescription("Configurar slowmode")
    .addIntegerOption(o => o.setName("segundos").setDescription("0 a 21600").setRequired(true).setMinValue(0).setMaxValue(21600)),

  new SlashCommandBuilder()
    .setName("lock")
    .setDescription("Bloquear el canal"),

  new SlashCommandBuilder()
    .setName("unlock")
    .setDescription("Desbloquear el canal"),

  new SlashCommandBuilder()
    .setName("role")
    .setDescription("Agregar o quitar un rol")
    .addStringOption(o => o.setName("accion").setDescription("Acción").setRequired(true)
      .addChoices(
        { name: "Agregar", value: "add" },
        { name: "Quitar", value: "remove" }
      ))
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true))
    .addRoleOption(o => o.setName("rol").setDescription("Rol").setRequired(true)),

  new SlashCommandBuilder()
    .setName("nickname")
    .setDescription("Cambiar apodo")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true))
    .addStringOption(o => o.setName("nombre").setDescription("Nuevo apodo").setRequired(true)),

  new SlashCommandBuilder()
    .setName("history")
    .setDescription("Ver historial de moderación")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true)),

  new SlashCommandBuilder()
    .setName("modlogs")
    .setDescription("Configurar canal de registros")
    .addChannelOption(o => o.setName("canal").setDescription("Canal").setRequired(true)
      .addChannelTypes(ChannelType.GuildText)),

  new SlashCommandBuilder()
    .setName("note")
    .setDescription("Guardar una nota")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true))
    .addStringOption(o => o.setName("texto").setDescription("Nota").setRequired(true)),

  new SlashCommandBuilder()
    .setName("anti")
    .setDescription("Administrar las protecciones")
    .addSubcommand(s => s.setName("status").setDescription("Ver estado de las protecciones"))
    .addSubcommand(s => s.setName("enable")
      .setDescription("Activar una protección")
      .addStringOption(o => o.setName("proteccion").setDescription("Protección").setRequired(true)
        .addChoices(
          { name: "Anti-Raid", value: "antiRaid" },
          { name: "Anti-Nuke", value: "antiNuke" },
          { name: "Anti-Spam", value: "antiSpam" },
          { name: "Anti-Flood", value: "antiFlood" },
          { name: "Anti-Mass-Mention", value: "antiMentions" },
          { name: "Anti-Phishing", value: "antiPhishing" },
          { name: "Anti-Webhook", value: "antiWebhook" },
          { name: "Anti-Bot", value: "antiBot" },
          { name: "Anti-Permission", value: "antiPermission" }
        )))
    .addSubcommand(s => s.setName("disable")
      .setDescription("Desactivar una protección")
      .addStringOption(o => o.setName("proteccion").setDescription("Protección").setRequired(true)
        .addChoices(
          { name: "Anti-Raid", value: "antiRaid" },
          { name: "Anti-Nuke", value: "antiNuke" },
          { name: "Anti-Spam", value: "antiSpam" },
          { name: "Anti-Flood", value: "antiFlood" },
          { name: "Anti-Mass-Mention", value: "antiMentions" },
          { name: "Anti-Phishing", value: "antiPhishing" },
          { name: "Anti-Webhook", value: "antiWebhook" },
          { name: "Anti-Bot", value: "antiBot" },
          { name: "Anti-Permission", value: "antiPermission" }
        ))),

  new SlashCommandBuilder()
    .setName("security")
    .setDescription("Herramientas de seguridad")
    .addSubcommand(s => s.setName("scan").setDescription("Revisar permisos y configuración"))
    .addSubcommand(s => s.setName("logs").setDescription("Ver registros recientes"))
    .addSubcommand(s => s.setName("lockdown").setDescription("Activar bloqueo de emergencia"))
    .addSubcommand(s => s.setName("unlockdown").setDescription("Desactivar bloqueo de emergencia")),

  new SlashCommandBuilder()
    .setName("whitelist")
    .setDescription("Administrar lista de confianza")
    .addStringOption(o => o.setName("accion").setDescription("Acción").setRequired(true)
      .addChoices(
        { name: "Agregar", value: "add" },
        { name: "Quitar", value: "remove" }
      ))
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true)),

  new SlashCommandBuilder()
    .setName("welcome")
    .setDescription("Configurar canal de bienvenida")
    .addChannelOption(o => o.setName("canal").setDescription("Canal").setRequired(true)
      .addChannelTypes(ChannelType.GuildText)),

  new SlashCommandBuilder()
    .setName("goodbye")
    .setDescription("Configurar canal de despedida")
    .addChannelOption(o => o.setName("canal").setDescription("Canal").setRequired(true)
      .addChannelTypes(ChannelType.GuildText)),

  new SlashCommandBuilder()
    .setName("autorole")
    .setDescription("Configurar rol automático")
    .addRoleOption(o => o.setName("rol").setDescription("Rol").setRequired(true)),

  new SlashCommandBuilder()
    .setName("ticket-setup")
    .setDescription("Configurar y publicar el panel de tickets")
    .addChannelOption(o => o.setName("categoria").setDescription("Categoría").setRequired(true)
      .addChannelTypes(ChannelType.GuildCategory))
    .addRoleOption(o => o.setName("soporte").setDescription("Rol del equipo de soporte")),

  new SlashCommandBuilder()
    .setName("ticket-close")
    .setDescription("Cerrar el ticket actual"),

  new SlashCommandBuilder()
    .setName("ticket-reopen")
    .setDescription("Reabrir un ticket cerrado"),

  new SlashCommandBuilder()
    .setName("ticket-add")
    .setDescription("Agregar usuario al ticket")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true)),

  new SlashCommandBuilder()
    .setName("ticket-remove")
    .setDescription("Quitar usuario del ticket")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true)),

  new SlashCommandBuilder()
    .setName("language")
    .setDescription("Cambiar idioma")
    .addStringOption(o => o.setName("idioma").setDescription("Idioma").setRequired(true)
      .addChoices(
        { name: "Español", value: "es" },
        { name: "English", value: "en" }
      ))
];

// ======================================
// HELP
// ======================================

function helpEmbed() {
  return new EmbedBuilder()
    .setColor(0x1677FF)
    .setTitle("🛡️ Sentinel Security — Help")
    .setDescription("Centro de comandos. También podés usar el prefijo `.`.")
    .addFields(
      {
        name: "🛠️ Moderación",
        value: "`/ban` `/unban` `/kick` `/timeout` `/untimeout`\n`/warn` `/unwarn` `/warnings` `/purge`\n`/slowmode` `/lock` `/unlock` `/role`\n`/nickname` `/history` `/note`",
        inline: false
      },
      {
        name: "🛡️ Protección",
        value: "`/anti status` `/anti enable` `/anti disable`\n`/security scan` `/security logs`\n`/security lockdown` `/security unlockdown`\n`/whitelist`",
        inline: false
      },
      {
        name: "⚙️ Administración",
        value: "`/modlogs` `/welcome` `/goodbye` `/autorole`\n`/ticket-setup` `/ticket-close` `/ticket-reopen`\n`/ticket-add` `/ticket-remove` `/language`",
        inline: false
      },
      {
        name: "ℹ️ Información",
        value: "`/ping` `/uptime` `/botinfo` `/serverinfo`\n`/userinfo` `/avatar` `/help`",
        inline: false
      }
    )
    .setFooter({ text: "Sentinel Security • Moderation & Protection" })
    .setTimestamp();
}

// ======================================
// MODERATION
// ======================================

async function moderate(ctx, action, target, reason = "Sin motivo") {
  const guild = ctx.guild;
  const actor = ctx.member?.user
    ? ctx.member
    : await guild.members.fetch(ctx.user.id).catch(() => null);

  if (!actor) return reply(ctx, "No pude verificar tus permisos.", 0xE74C3C);

  const member = await guild.members.fetch(target.id).catch(() => null);

  if (member && !canManageTarget(actor, member)) {
    return reply(ctx, "No podés moderar a alguien con un rol igual o superior al tuyo.", 0xE74C3C);
  }

  const botMember = await getBotMember(guild);

  if (member && !canManageTarget(botMember, member)) {
    return reply(ctx, "Mi rol está por debajo del usuario afectado.", 0xE74C3C);
  }

  try {
    if (action === "ban") {
      if (!await botHas(guild, PermissionsBitField.Flags.BanMembers)) {
        return reply(ctx, "Me falta el permiso Ban Members.", 0xE74C3C);
      }
      await guild.members.ban(target.id, { reason });
    }

    if (action === "kick") {
      if (!member) return reply(ctx, "Ese usuario no está en el servidor.", 0xE74C3C);
      if (!await botHas(guild, PermissionsBitField.Flags.KickMembers)) {
        return reply(ctx, "Me falta el permiso Kick Members.", 0xE74C3C);
      }
      await member.kick(reason);
    }

    addCase(guild.id, {
      action,
      user: target.id,
      moderator: actor.id,
      reason
    });

    await log(guild, `Moderación: ${action}`,
      `Usuario: <@${target.id}>\nModerador: <@${actor.id}>\nMotivo: ${reason}`);

    return reply(ctx, `Acción **${action}** realizada sobre <@${target.id}>.`);
  } catch (error) {
    console.error("Error de moderación:", error);
    return reply(ctx, "No pude realizar la acción. Revisá permisos y jerarquía.", 0xE74C3C);
  }
}

// ======================================
// LOCKDOWN
// ======================================

async function setLockdown(guild, enabled, ctx) {
  const config = getServer(guild.id);

  if (!hasPermission(ctx.member, PermissionsBitField.Flags.Administrator) &&
      !hasPermission(ctx.member, PermissionsBitField.Flags.ManageChannels)) {
    return reply(ctx, "Necesitás Administrador o Manage Channels.", 0xE74C3C);
  }

  if (!await botHas(guild, PermissionsBitField.Flags.ManageChannels)) {
    return reply(ctx, "Me falta Manage Channels.", 0xE74C3C);
  }

  if (enabled) {
    config.security.lockdown = true;
    saveData();

    let changed = 0;

    for (const channel of guild.channels.cache.values()) {
      if (!channel.isTextBased() || !channel.permissionOverwrites) continue;

      const success = await channel.permissionOverwrites.edit(
        guild.roles.everyone,
        { SendMessages: false }
      ).then(() => true).catch(() => false);

      if (success) changed++;
    }

    await log(guild, "Bloqueo de emergencia",
      `Activado por <@${ctx.user?.id || ctx.author.id}>. Canales modificados: ${changed}.`,
      0xE74C3C);

    return reply(ctx, `Bloqueo activado. Canales modificados: ${changed}.`, 0xE74C3C);
  }

  config.security.lockdown = false;
  saveData();

  await log(guild, "Bloqueo de emergencia",
    `Desactivado por <@${ctx.user?.id || ctx.author.id}>.`);

  return reply(ctx,
    "Modo de emergencia desactivado. Revisá manualmente los permisos de los canales para restaurarlos.");
}

// ======================================
// TICKET SYSTEM
// ======================================

function ticketButtons(closed = false) {
  const row = new ActionRowBuilder();

  if (!closed) {
    row.addComponents(
      new ButtonBuilder()
        .setCustomId("sentinel_ticket_close")
        .setLabel("Cerrar ticket")
        .setEmoji("🔒")
        .setStyle(ButtonStyle.Danger)
    );
  } else {
    row.addComponents(
      new ButtonBuilder()
        .setCustomId("sentinel_ticket_reopen")
        .setLabel("Reabrir ticket")
        .setEmoji("🔓")
        .setStyle(ButtonStyle.Success)
    );
  }

  return [row];
}

function isTicketStaff(interaction, config) {
  return interaction.memberPermissions?.has(PermissionsBitField.Flags.ManageChannels) ||
    (config.ticketSupportRole &&
      interaction.member?.roles?.cache?.has(config.ticketSupportRole));
}

async function createTicket(interaction) {
  const guild = interaction.guild;
  const config = getServer(guild.id);

  if (!config.ticketCategory) {
    return reply(interaction, "Primero configurá los tickets con `/ticket-setup`.", 0xE74C3C);
  }

  const category = guild.channels.cache.get(config.ticketCategory);

  if (!category || category.type !== ChannelType.GuildCategory) {
    return reply(interaction, "La categoría configurada ya no existe. Volvé a configurar los tickets.", 0xE74C3C);
  }

  const existing = Object.entries(config.tickets).find(([channelId, ticket]) =>
    ticket.ownerId === interaction.user.id &&
    ticket.status === "open" &&
    guild.channels.cache.has(channelId)
  );

  if (existing) {
    return reply(interaction, `Ya tenés un ticket abierto: <#${existing[0]}>`);
  }

  if (!await botHas(guild, PermissionsBitField.Flags.ManageChannels)) {
    return reply(interaction, "Me falta Manage Channels para crear tickets.", 0xE74C3C);
  }

  const permissionOverwrites = [
    {
      id: guild.roles.everyone.id,
      deny: [PermissionsBitField.Flags.ViewChannel]
    },
    {
      id: interaction.user.id,
      allow: [
        PermissionsBitField.Flags.ViewChannel,
        PermissionsBitField.Flags.SendMessages,
        PermissionsBitField.Flags.ReadMessageHistory,
        PermissionsBitField.Flags.AttachFiles
      ]
    },
    {
      id: client.user.id,
      allow: [
        PermissionsBitField.Flags.ViewChannel,
        PermissionsBitField.Flags.SendMessages,
        PermissionsBitField.Flags.ReadMessageHistory,
        PermissionsBitField.Flags.ManageChannels
      ]
    }
  ];

  if (config.ticketSupportRole) {
    permissionOverwrites.push({
      id: config.ticketSupportRole,
      allow: [
        PermissionsBitField.Flags.ViewChannel,
        PermissionsBitField.Flags.SendMessages,
        PermissionsBitField.Flags.ReadMessageHistory
      ]
    });
  }

  try {
    const channel = await guild.channels.create({
      name: `ticket-${interaction.user.username}`.toLowerCase()
        .replace(/[^a-z0-9-]/g, "-").slice(0, 80),
      type: ChannelType.GuildText,
      parent: category.id,
      permissionOverwrites,
      topic: `Sentinel ticket owner:${interaction.user.id}`
    });

    config.tickets[channel.id] = {
      ownerId: interaction.user.id,
      status: "open",
      createdAt: new Date().toISOString(),
      closedAt: null
    };

    saveData();

    await channel.send({
      content: `<@${interaction.user.id}>`,
      embeds: [
        makeEmbed("Ticket abierto",
          "¡Hola! Contanos qué necesitás y el equipo de soporte te responderá pronto.")
      ],
      components: ticketButtons(false)
    });

    await ticketLog(guild, "Ticket creado",
      `Canal: ${channel}\nUsuario: <@${interaction.user.id}>`);

    return reply(interaction, `Tu ticket fue creado: ${channel}`);
  } catch (error) {
    console.error("Error creando ticket:", error);
    return reply(interaction, "No pude crear el ticket. Revisá los permisos y la categoría.", 0xE74C3C);
  }
}

async function closeTicket(channel, user, config) {
  const ticket = config.tickets[channel.id];
  if (!ticket) return false;

  const guild = channel.guild;

  await channel.permissionOverwrites.edit(ticket.ownerId, {
    SendMessages: false,
    ViewChannel: true
  });

  if (config.ticketSupportRole) {
    await channel.permissionOverwrites.edit(config.ticketSupportRole, {
      ViewChannel: true,
      SendMessages: true
    }).catch(() => {});
  }

  ticket.status = "closed";
  ticket.closedAt = new Date().toISOString();
  saveData();

  await channel.send({
    embeds: [makeEmbed("Ticket cerrado",
      `Cerrado por <@${user.id}>. El equipo puede reabrirlo si es necesario.`)],
    components: ticketButtons(true)
  });

  await ticketLog(guild, "Ticket cerrado",
    `Canal: <#${channel.id}>\nCerrado por: <@${user.id}>`);

  return true;
}

async function reopenTicket(channel, user, config) {
  const ticket = config.tickets[channel.id];
  if (!ticket) return false;

  await channel.permissionOverwrites.edit(ticket.ownerId, {
    ViewChannel: true,
    SendMessages: true,
    ReadMessageHistory: true
  });

  ticket.status = "open";
  ticket.closedAt = null;
  saveData();

  await channel.send({
    embeds: [makeEmbed("Ticket reabierto", `Reabierto por <@${user.id}>.`)],
    components: ticketButtons(false)
  });

  await ticketLog(channel.guild, "Ticket reabierto",
    `Canal: <#${channel.id}>\nReabierto por: <@${user.id}>`);

  return true;
}

// ======================================
// SLASH HANDLER
// ======================================

async function slashCommand(interaction) {
  const guild = interaction.guild;
  const config = getServer(guild.id);
  const name = interaction.commandName;
  const user = interaction.user;
  const actor = await guild.members.fetch(user.id).catch(() => null);

  if (!actor) return reply(interaction, "No pude verificar tu usuario.", 0xE74C3C);

  const permissions = {
    ban: PermissionsBitField.Flags.BanMembers,
    unban: PermissionsBitField.Flags.BanMembers,
    kick: PermissionsBitField.Flags.KickMembers,
    timeout: PermissionsBitField.Flags.ModerateMembers,
    untimeout: PermissionsBitField.Flags.ModerateMembers,
    warn: PermissionsBitField.Flags.ManageMessages,
    unwarn: PermissionsBitField.Flags.ManageMessages,
    warnings: PermissionsBitField.Flags.ManageMessages,
    purge: PermissionsBitField.Flags.ManageMessages,
    slowmode: PermissionsBitField.Flags.ManageChannels,
    lock: PermissionsBitField.Flags.ManageChannels,
    unlock: PermissionsBitField.Flags.ManageChannels,
    role: PermissionsBitField.Flags.ManageRoles,
    nickname: PermissionsBitField.Flags.ManageNicknames,
    history: PermissionsBitField.Flags.ViewAuditLog,
    modlogs: PermissionsBitField.Flags.ManageGuild,
    note: PermissionsBitField.Flags.ManageMessages,
    anti: PermissionsBitField.Flags.ManageGuild,
    security: PermissionsBitField.Flags.ManageGuild,
    whitelist: PermissionsBitField.Flags.ManageGuild,
    welcome: PermissionsBitField.Flags.ManageGuild,
    goodbye: PermissionsBitField.Flags.ManageGuild,
    autorole: PermissionsBitField.Flags.ManageRoles,
    "ticket-setup": PermissionsBitField.Flags.ManageChannels,
    "ticket-add": PermissionsBitField.Flags.ManageChannels,
    "ticket-remove": PermissionsBitField.Flags.ManageChannels,
    "ticket-reopen": PermissionsBitField.Flags.ManageChannels,
    language: PermissionsBitField.Flags.ManageGuild
  };

  if (permissions[name] && !hasPermission(actor, permissions[name])) {
    return reply(interaction, "No tenés permiso para ejecutar este comando.", 0xE74C3C);
  }

  const target = interaction.options.getUser("usuario");
  const member = target
    ? await guild.members.fetch(target.id).catch(() => null)
    : null;

  const reason = interaction.options.getString("motivo") || "Sin motivo";

  // INFORMATION

  if (name === "help") {
    return interaction.editReply({ embeds: [helpEmbed()] });
  }

  if (name === "ping") {
    return reply(interaction, `Latencia de API: **${client.ws.ping} ms**.`);
  }

  if (name === "uptime") {
    const seconds = Math.floor(client.uptime / 1000);
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return reply(interaction, `Activo durante **${days}d ${hours}h ${minutes}m**.`);
  }

  if (name === "botinfo") {
    return reply(interaction,
      `**Nombre:** ${client.user.tag}\n**Servidores:** ${client.guilds.cache.size}\n**Usuarios aproximados:** ${client.guilds.cache.reduce((n, g) => n + (g.memberCount || 0), 0)}\n**Discord.js:** v14`);
  }

  if (name === "serverinfo") {
    return reply(interaction,
      `**Servidor:** ${guild.name}\n**ID:** ${guild.id}\n**Miembros:** ${guild.memberCount}\n**Canales:** ${guild.channels.cache.size}\n**Creado:** <t:${Math.floor(guild.createdTimestamp / 1000)}:D>`);
  }

  if (name === "userinfo") {
    const selected = target || user;
    const selectedMember = await guild.members.fetch(selected.id).catch(() => null);
    return reply(interaction,
      `**Usuario:** ${selected.tag}\n**ID:** ${selected.id}\n**Cuenta creada:** <t:${Math.floor(selected.createdTimestamp / 1000)}:F>\n**Entró al servidor:** ${selectedMember ? `<t:${Math.floor(selectedMember.joinedTimestamp / 1000)}:F>` : "No disponible"}`);
  }

  if (name === "avatar") {
    const selected = target || user;
    const e = makeEmbed("Avatar", `[Abrir imagen](${selected.displayAvatarURL({ size: 1024 })})`)
      .setImage(selected.displayAvatarURL({ size: 1024 }));
    return interaction.editReply({ embeds: [e] });
  }

  // MODERATION

  if (["ban", "kick"].includes(name)) {
    if (!target) return reply(interaction, "Elegí un usuario.");
    return moderate(interaction, name, target, reason);
  }

  if (name === "unban") {
    if (!await requireBotPermission(interaction, PermissionsBitField.Flags.BanMembers)) return;

    const id = interaction.options.getString("id");

    if (!/^\d{17,20}$/.test(id)) {
      return reply(interaction, "El ID no es válido.", 0xE74C3C);
    }

    try {
      await guild.members.unban(id, reason);
      addCase(guild.id, { action: "unban", user: id, moderator: user.id, reason });
      return reply(interaction, "Usuario desbaneado correctamente.");
    } catch {
      return reply(interaction, "No pude desbanear ese ID.", 0xE74C3C);
    }
  }

  if (name === "timeout" || name === "untimeout") {
    if (!member) return reply(interaction, "El usuario no está en este servidor.");

    if (!canManageTarget(actor, member)) {
      return reply(interaction, "No podés moderar a alguien con un rol igual o superior al tuyo.", 0xE74C3C);
    }

    if (!await botHas(guild, PermissionsBitField.Flags.ModerateMembers)) {
      return reply(interaction, "Me falta Moderate Members.", 0xE74C3C);
    }

    if (!canManageTarget(await getBotMember(guild), member)) {
      return reply(interaction, "Mi rol está por debajo del usuario.", 0xE74C3C);
    }

    try {
      if (name === "timeout") {
        const minutes = interaction.options.getInteger("minutos");
        await member.timeout(minutes * 60000, reason);
        addCase(guild.id, { action: "timeout", user: target.id, moderator: user.id, reason });
        await log(guild, "Timeout", `<@${target.id}> recibió timeout de ${minutes} minutos.`);
        return reply(interaction, `Timeout aplicado durante ${minutes} minutos.`);
      }

      await member.timeout(null, "Timeout retirado");
      addCase(guild.id, { action: "untimeout", user: target.id, moderator: user.id, reason });
      return reply(interaction, "Timeout eliminado.");
    } catch (error) {
      console.error(error);
      return reply(interaction, "No pude modificar el timeout.", 0xE74C3C);
    }
  }

  if (name === "warn") {
    config.warnings[target.id] ??= [];
    config.warnings[target.id].push({
      moderator: user.id,
      reason: interaction.options.getString("motivo"),
      date: new Date().toISOString()
    });

    addCase(guild.id, { action: "warn", user: target.id, moderator: user.id, reason });
    saveData();
    await log(guild, "Advertencia", `<@${target.id}> recibió una advertencia de <@${user.id}>.`);
    return reply(interaction, "Advertencia registrada.");
  }

  if (name === "warnings" || name === "unwarn") {
    const warnings = config.warnings[target.id] || [];

    if (name === "warnings") {
      return reply(interaction, warnings.length
        ? warnings.map((w, i) => `**${i + 1}.** ${w.reason} — <t:${Math.floor(new Date(w.date).getTime() / 1000)}:R>`).join("\n")
        : "Este usuario no tiene advertencias.");
    }

    const index = interaction.options.getInteger("numero") - 1;

    if (index < 0 || index >= warnings.length) {
      return reply(interaction, "Número de advertencia no válido.");
    }

    warnings.splice(index, 1);
    saveData();
    return reply(interaction, "Advertencia eliminada.");
  }

  if (name === "purge") {
    if (!await requireBotPermission(interaction, PermissionsBitField.Flags.ManageMessages, interaction.channel)) return;

    const amount = interaction.options.getInteger("cantidad");
    const deleted = await interaction.channel.bulkDelete(amount, true).catch(() => null);

    return reply(interaction,
      deleted ? `Eliminé ${deleted.size} mensajes.` : "No pude eliminar los mensajes.", 
      deleted ? 0x1677FF : 0xE74C3C);
  }

  if (name === "slowmode") {
    if (!await requireBotPermission(interaction, PermissionsBitField.Flags.ManageChannels, interaction.channel)) return;

    const seconds = interaction.options.getInteger("segundos");

    try {
      await interaction.channel.setRateLimitPerUser(seconds);
      return reply(interaction, `Slowmode configurado en ${seconds} segundos.`);
    } catch {
      return reply(interaction, "No pude cambiar el slowmode.", 0xE74C3C);
    }
  }

  if (name === "lock" || name === "unlock") {
    if (!await requireBotPermission(interaction, PermissionsBitField.Flags.ManageChannels, interaction.channel)) return;

    const value = name === "lock" ? false : null;

    try {
      await interaction.channel.permissionOverwrites.edit(guild.roles.everyone, {
        SendMessages: value
      });
      return reply(interaction, name === "lock" ? "Canal bloqueado." : "Canal desbloqueado.");
    } catch {
      return reply(interaction, "No pude modificar los permisos del canal.", 0xE74C3C);
    }
  }

  if (name === "role") {
    const role = interaction.options.getRole("rol");
    const action = interaction.options.getString("accion");
    const botMember = await getBotMember(guild);

    if (!member || !canManageTarget(actor, member) ||
        !canManageTarget(botMember, member) ||
        role.position >= botMember.roles.highest.position ||
        (role.position >= actor.roles.highest.position && actor.id !== guild.ownerId)) {
      return reply(interaction, "No podés modificar ese usuario o rol por jerarquía.", 0xE74C3C);
    }

    try {
      await member.roles[action](role);
      return reply(interaction, "Rol actualizado.");
    } catch {
      return reply(interaction, "No pude modificar el rol.", 0xE74C3C);
    }
  }

  if (name === "nickname") {
    const nickname = interaction.options.getString("nombre");
    const botMember = await getBotMember(guild);

    if (!member || !canManageTarget(actor, member) || !canManageTarget(botMember, member)) {
      return reply(interaction, "No podés cambiar el apodo de ese usuario.", 0xE74C3C);
    }

    try {
      await member.setNickname(nickname);
      return reply(interaction, "Apodo actualizado.");
    } catch {
      return reply(interaction, "No pude cambiar el apodo.", 0xE74C3C);
    }
  }

  if (name === "history") {
    const cases = config.cases.filter(c => c.user === target.id).slice(-10);
    return reply(interaction, cases.length
      ? cases.map(c => `**${c.action}** — ${c.reason || "Sin motivo"} — <t:${Math.floor(new Date(c.date).getTime() / 1000)}:R>`).join("\n")
      : "No hay registros para este usuario.");
  }

  if (name === "modlogs") {
    config.logs = interaction.options.getChannel("canal").id;
    saveData();
    return reply(interaction, "Canal de registros configurado.");
  }

  if (name === "note") {
    config.notes[target.id] ??= [];
    config.notes[target.id].push({
      moderator: user.id,
      text: interaction.options.getString("texto"),
      date: new Date().toISOString()
    });
    saveData();
    return reply(interaction, "Nota guardada.");
  }

  // ANTI PROTECTION

  if (name === "anti") {
    const sub = interaction.options.getSubcommand();

    if (sub === "status") {
      const lines = Object.entries(config.security)
        .filter(([key]) => key !== "lockdown")
        .map(([key, value]) => `**${key}:** ${value ? "🟢 Activado" : "🔴 Desactivado"}`);

      return reply(interaction, lines.join("\n"));
    }

    const key = interaction.options.getString("proteccion");
    config.security[key] = sub === "enable";
    saveData();

    return reply(interaction, `**${key}** ${sub === "enable" ? "activado" : "desactivado"}.`);
  }

  if (name === "security") {
    const sub = interaction.options.getSubcommand();

    if (sub === "lockdown" || sub === "unlockdown") {
      return setLockdown(guild, sub === "lockdown", interaction);
    }

    if (sub === "logs") {
      const cases = config.cases.slice(-10);
      return reply(interaction, cases.length
        ? cases.map(c => `**${c.action}** — <@${c.user}> — ${c.reason || "Sin motivo"}`).join("\n")
        : "Todavía no hay registros de moderación.");
    }

    if (sub === "scan") {
      const botMember = await getBotMember(guild);
      const checks = [
        ["View Channels", PermissionsBitField.Flags.ViewChannel],
        ["Send Messages", PermissionsBitField.Flags.SendMessages],
        ["Manage Channels", PermissionsBitField.Flags.ManageChannels],
        ["Manage Messages", PermissionsBitField.Flags.ManageMessages],
        ["Moderate Members", PermissionsBitField.Flags.ModerateMembers],
        ["Kick Members", PermissionsBitField.Flags.KickMembers],
        ["Ban Members", PermissionsBitField.Flags.BanMembers],
        ["Manage Roles", PermissionsBitField.Flags.ManageRoles],
        ["View Audit Log", PermissionsBitField.Flags.ViewAuditLog]
      ];

      const result = checks.map(([label, permission]) =>
        `${botMember.permissions.has(permission) ? "🟢" : "🔴"} ${label}`
      );

      return reply(interaction, `**Revisión de permisos del bot**\n${result.join("\n")}\n\nEste análisis revisa permisos; no garantiza protección total.`);
    }
  }

  if (name === "whitelist") {
    const action = interaction.options.getString("accion");
    const id = target.id;

    if (action === "add" && !config.whitelist.includes(id)) {
      config.whitelist.push(id);
    }

    if (action === "remove") {
      config.whitelist = config.whitelist.filter(x => x !== id);
    }

    saveData();
    return reply(interaction, "Lista de confianza actualizada.");
  }

  // SERVER CONFIGURATION

  if (name === "welcome" || name === "goodbye") {
    config[name] = interaction.options.getChannel("canal").id;
    saveData();
    return reply(interaction, `Canal de ${name} configurado.`);
  }

  if (name === "autorole") {
    const role = interaction.options.getRole("rol");
    const botMember = await getBotMember(guild);

    if (role.position >= botMember.roles.highest.position) {
      return reply(interaction, "Mi rol debe estar por encima del rol automático.", 0xE74C3C);
    }

    config.autorole = role.id;
    saveData();
    return reply(interaction, "Autorole configurado.");
  }

  if (name === "language") {
    config.language = interaction.options.getString("idioma");
    saveData();
    return reply(interaction, `Idioma configurado: ${config.language}`);
  }

  // TICKETS

  if (name === "ticket-setup") {
    const category = interaction.options.getChannel("categoria");
    const supportRole = interaction.options.getRole("soporte");

    config.ticketCategory = category.id;
    config.ticketSupportRole = supportRole?.id || null;
    saveData();

    const panel = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId("sentinel_ticket_create")
        .setLabel("Crear ticket")
        .setEmoji("🎫")
        .setStyle(ButtonStyle.Primary)
    );

    await interaction.channel.send({
      embeds: [makeEmbed("Centro de soporte",
        "¿Necesitás ayuda? Presioná el botón para abrir un ticket privado.")],
      components: [panel]
    });

    return reply(interaction, "Panel de tickets publicado y configurado.");
  }

  if (name === "ticket-close" || name === "ticket-reopen") {
    const ticket = config.tickets[interaction.channel.id];

    if (!ticket) {
      return reply(interaction, "Este canal no está registrado como ticket.", 0xE74C3C);
    }

    const staff = isTicketStaff(interaction, config);
    const owner = ticket.ownerId === user.id;

    if (name === "ticket-close" && !owner && !staff) {
      return reply(interaction, "Solo el dueño del ticket o soporte puede cerrarlo.", 0xE74C3C);
    }

    if (name === "ticket-reopen" && !staff) {
      return reply(interaction, "Solo el equipo de soporte puede reabrirlo.", 0xE74C3C);
    }

    if (name === "ticket-close") {
      if (ticket.status === "closed") return reply(interaction, "Este ticket ya está cerrado.");
      await closeTicket(interaction.channel, user, config);
      return reply(interaction, "Ticket cerrado. El canal se conservó para el historial.");
    }

    if (ticket.status === "open") return reply(interaction, "Este ticket ya está abierto.");
    await reopenTicket(interaction.channel, user, config);
    return reply(interaction, "Ticket reabierto.");
  }

  if (name === "ticket-add" || name === "ticket-remove") {
    const ticket = config.tickets[interaction.channel.id];
    if (!ticket) return reply(interaction, "Este canal no está registrado como ticket.");

    const selected = interaction.options.getUser("usuario");
    const add = name === "ticket-add";

    try {
      await interaction.channel.permissionOverwrites.edit(selected.id, {
        ViewChannel: add,
        SendMessages: add,
        ReadMessageHistory: add
      });

      return reply(interaction, add
        ? `Se agregó a <@${selected.id}> al ticket.`
        : `Se quitó a <@${selected.id}> del ticket.`);
    } catch {
      return reply(interaction, "No pude modificar los permisos del ticket.", 0xE74C3C);
    }
  }
}

// ======================================
// PREFIX COMMANDS
// ======================================

async function prefixCommand(message) {
  if (!message.guild || message.author.bot) return;

  const args = message.content.slice(PREFIX.length).trim().split(/\s+/);
  const command = (args.shift() || "").toLowerCase();
  if (!command) return;

  const guild = message.guild;
  const config = getServer(guild.id);
  const actor = message.member;
  const target = await getMember(guild, args[0]);
  const reason = args.slice(1).join(" ") || "Sin motivo";

  const permissions = {
    ban: PermissionsBitField.Flags.BanMembers,
    unban: PermissionsBitField.Flags.BanMembers,
    kick: PermissionsBitField.Flags.KickMembers,
    timeout: PermissionsBitField.Flags.ModerateMembers,
    untimeout: PermissionsBitField.Flags.ModerateMembers,
    warn: PermissionsBitField.Flags.ManageMessages,
    unwarn: PermissionsBitField.Flags.ManageMessages,
    warnings: PermissionsBitField.Flags.ManageMessages,
    purge: PermissionsBitField.Flags.ManageMessages,
    slowmode: PermissionsBitField.Flags.ManageChannels,
    lock: PermissionsBitField.Flags.ManageChannels,
    unlock: PermissionsBitField.Flags.ManageChannels,
    role: PermissionsBitField.Flags.ManageRoles,
    nickname: PermissionsBitField.Flags.ManageNicknames,
    modlogs: PermissionsBitField.Flags.ManageGuild,
    note: PermissionsBitField.Flags.ManageMessages,
    security: PermissionsBitField.Flags.ManageGuild,
    "security-status": PermissionsBitField.Flags.ManageGuild,
    whitelist: PermissionsBitField.Flags.ManageGuild,
    lockdown: PermissionsBitField.Flags.ManageChannels,
    unlockdown: PermissionsBitField.Flags.ManageChannels,
    welcome: PermissionsBitField.Flags.ManageGuild,
    goodbye: PermissionsBitField.Flags.ManageGuild,
    autorole: PermissionsBitField.Flags.ManageRoles,
    "ticket-setup": PermissionsBitField.Flags.ManageChannels,
    "ticket-close": PermissionsBitField.Flags.ManageChannels,
    "ticket-reopen": PermissionsBitField.Flags.ManageChannels,
    "ticket-add": PermissionsBitField.Flags.ManageChannels,
    "ticket-remove": PermissionsBitField.Flags.ManageChannels,
    language: PermissionsBitField.Flags.ManageGuild
  };

  if (permissions[command] && !hasPermission(actor, permissions[command])) {
    return reply(message, "No tenés permiso para ese comando.", 0xE74C3C);
  }

  if (command === "help") {
    return message.reply({ embeds: [helpEmbed()] });
  }

  if (command === "ping") {
    return reply(message, `Latencia: **${client.ws.ping} ms**.`);
  }

  if (command === "uptime") {
    return reply(message, `Tiempo activo: **${Math.floor(client.uptime / 1000)} segundos**.`);
  }

  if (command === "ban" || command === "kick") {
    if (!target) return reply(message, "Uso: `.ban @usuario motivo` o `.kick @usuario motivo`.");
    return moderate(message, command, target.user, reason);
  }

  if (command === "unban") {
    if (!await requireBotPermission(message, PermissionsBitField.Flags.BanMembers)) return;
    const id = args[0];

    if (!/^\d{17,20}$/.test(id || "")) return reply(message, "Uso: `.unban ID`.");

    try {
      await guild.members.unban(id, reason);
      addCase(guild.id, { action: "unban", user: id, moderator: message.author.id, reason });
      return reply(message, "Usuario desbaneado.");
    } catch {
      return reply(message, "No pude desbanear ese ID.", 0xE74C3C);
    }
  }

  if (command === "timeout" || command === "untimeout") {
    if (!target) return reply(message, "Indicá un usuario válido.");
    if (!canManageTarget(actor, target) ||
        !canManageTarget(await getBotMember(guild), target)) {
      return reply(message, "No podés modificar a ese usuario por jerarquía.", 0xE74C3C);
    }

    if (!await requireBotPermission(message, PermissionsBitField.Flags.ModerateMembers)) return;

    try {
      if (command === "timeout") {
        const minutes = Number(args[1]);
        if (!Number.isInteger(minutes) || minutes < 1 || minutes > 40320) {
          return reply(message, "Uso: `.timeout @usuario minutos motivo`.");
        }

        await target.timeout(minutes * 60000, args.slice(2).join(" ") || "Sin motivo");
        addCase(guild.id, { action: "timeout", user: target.id, moderator: message.author.id, reason });
        return reply(message, `Timeout aplicado durante ${minutes} minutos.`);
      }

      await target.timeout(null);
      addCase(guild.id, { action: "untimeout", user: target.id, moderator: message.author.id, reason });
      return reply(message, "Timeout eliminado.");
    } catch {
      return reply(message, "No pude modificar el timeout.", 0xE74C3C);
    }
  }

  if (command === "warn") {
    if (!target || !args[1]) return reply(message, "Uso: `.warn @usuario motivo`.");
    config.warnings[target.id] ??= [];
    config.warnings[target.id].push({
      moderator: message.author.id,
      reason: args.slice(1).join(" "),
      date: new Date().toISOString()
    });
    addCase(guild.id, { action: "warn", user: target.id, moderator: message.author.id, reason: args.slice(1).join(" ") });
    saveData();
    await log(guild, "Advertencia", `<@${target.id}> recibió una advertencia.`);
    return reply(message, "Advertencia registrada.");
  }

  if (command === "warnings" || command === "unwarn") {
    if (!target) return reply(message, `Uso: \`.${command} @usuario\`.`);
    const warnings = config.warnings[target.id] || [];

    if (command === "warnings") {
      return reply(message, warnings.length
        ? warnings.map((w, i) => `**${i + 1}.** ${w.reason}`).join("\n")
        : "Este usuario no tiene advertencias.");
    }

    const index = Number(args[1]) - 1;
    if (!Number.isInteger(index) || index < 0 || index >= warnings.length) {
      return reply(message, "Uso: `.unwarn @usuario número`.");
    }

    warnings.splice(index, 1);
    saveData();
    return reply(message, "Advertencia eliminada.");
  }

  if (command === "purge") {
    if (!await requireBotPermission(message, PermissionsBitField.Flags.ManageMessages, message.channel)) return;
    const amount = Number(args[0]);

    if (!Number.isInteger(amount) || amount < 1 || amount > 100) {
      return reply(message, "Uso: `.purge 1-100`.");
    }

    const deleted = await message.channel.bulkDelete(amount, true).catch(() => null);
    return reply(message, deleted ? `Eliminé ${deleted.size} mensajes.` : "No pude eliminar mensajes.", deleted ? 0x1677FF : 0xE74C3C);
  }

  if (command === "slowmode") {
    if (!await requireBotPermission(message, PermissionsBitField.Flags.ManageChannels, message.channel)) return;
    const seconds = Number(args[0]);

    if (!Number.isInteger(seconds) || seconds < 0 || seconds > 21600) {
      return reply(message, "Uso: `.slowmode 0-21600`.");
    }

    await message.channel.setRateLimitPerUser(seconds)
      .then(() => reply(message, `Slowmode: ${seconds} segundos.`))
      .catch(() => reply(message, "No pude cambiar el slowmode.", 0xE74C3C));
    return;
  }

  if (command === "lock" || command === "unlock") {
    if (!await requireBotPermission(message, PermissionsBitField.Flags.ManageChannels, message.channel)) return;
    await message.channel.permissionOverwrites.edit(guild.roles.everyone, {
      SendMessages: command === "lock" ? false : null
    }).then(() => reply(message, command === "lock" ? "Canal bloqueado." : "Canal desbloqueado."))
      .catch(() => reply(message, "No pude cambiar los permisos.", 0xE74C3C));
    return;
  }

  if (command === "modlogs") {
    const channel = message.mentions.channels.first();
    if (!channel?.isTextBased()) return reply(message, "Uso: `.modlogs #canal`.");
    config.logs = channel.id;
    saveData();
    return reply(message, "Canal de logs configurado.");
  }

  if (command === "welcome" || command === "goodbye") {
    const channel = message.mentions.channels.first();
    if (!channel?.isTextBased()) return reply(message, `Uso: \`.${command} #canal\`.`);
    config[command] = channel.id;
    saveData();
    return reply(message, `Canal de ${command} configurado.`);
  }

  if (command === "autorole") {
    const role = message.mentions.roles.first();
    const botMember = await getBotMember(guild);
    if (!role) return reply(message, "Uso: `.autorole @rol`.");
    if (role.position >= botMember.roles.highest.position) {
      return reply(message, "Mi rol debe estar por encima del rol automático.", 0xE74C3C);
    }
    config.autorole = role.id;
    saveData();
    return reply(message, "Autorole configurado.");
  }

  if (command === "security" || command === "anti") {
    const key = args[0];
    const value = args[1]?.toLowerCase();

    if (key === "status") {
      return reply(message, Object.entries(config.security)
        .map(([k, v]) => `**${k}:** ${v ? "Activado" : "Desactivado"}`).join("\n"));
    }

    const allowed = Object.keys(config.security).filter(k => k !== "lockdown");
    if (!allowed.includes(key) || !["on", "off"].includes(value)) {
      return reply(message, "Uso: `.anti antiSpam on/off` o `.anti status`.");
    }

    config.security[key] = value === "on";
    saveData();
    return reply(message, `${key}: ${value}`);
  }

  if (command === "security-status") {
    return reply(message, Object.entries(config.security)
      .map(([k, v]) => `**${k}:** ${v ? "Activado" : "Desactivado"}`).join("\n"));
  }

  if (command === "whitelist") {
    const action = args[0];
    const id = args[1]?.replace(/[<@!>]/g, "");

    if (!["add", "remove"].includes(action) || !/^\d{17,20}$/.test(id || "")) {
      return reply(message, "Uso: `.whitelist add/remove ID`.");
    }

    if (action === "add" && !config.whitelist.includes(id)) config.whitelist.push(id);
    if (action === "remove") config.whitelist = config.whitelist.filter(x => x !== id);

    saveData();
    return reply(message, "Lista de confianza actualizada.");
  }

  if (command === "lockdown" || command === "unlockdown") {
    return setLockdown(guild, command === "lockdown", message);
  }

  if (command === "language") {
    if (!["es", "en"].includes(args[0])) return reply(message, "Uso: `.language es/en`.");
    config.language = args[0];
    saveData();
    return reply(message, `Idioma: ${args[0]}`);
  }

  if (command === "note") {
    if (!target || !args[1]) return reply(message, "Uso: `.note @usuario texto`.");
    config.notes[target.id] ??= [];
    config.notes[target.id].push({
      moderator: message.author.id,
      text: args.slice(1).join(" "),
      date: new Date().toISOString()
    });
    saveData();
    return reply(message, "Nota guardada.");
  }

  if (command === "history") {
    const id = args[0]?.replace(/[<@!>]/g, "");
    if (!id) return reply(message, "Uso: `.history ID`.");
    const cases = config.cases.filter(c => c.user === id).slice(-10);
    return reply(message, cases.length
      ? cases.map(c => `**${c.action}** — ${c.reason || "Sin motivo"}`).join("\n")
      : "No hay registros para ese usuario.");
  }

  if (command === "ticket-setup") {
    const category = message.mentions.channels.first();
    if (!category || category.type !== ChannelType.GuildCategory) {
      return reply(message, "Uso: `.ticket-setup #categoría`.");
    }

    config.ticketCategory = category.id;
    saveData();

    await message.channel.send({
      embeds: [makeEmbed("Centro de soporte", "Presioná el botón para crear un ticket.")],
      components: [
        new ActionRowBuilder().addComponents(
          new ButtonBuilder()
            .setCustomId("sentinel_ticket_create")
            .setLabel("Crear ticket")
            .setEmoji("🎫")
            .setStyle(ButtonStyle.Primary)
        )
      ]
    });

    return reply(message, "Panel de tickets creado.");
  }

  if (command.startsWith("ticket-")) {
    const ticket = config.tickets[message.channel.id];
    if (!ticket) return reply(message, "Este canal no está registrado como ticket.");

    const staff = message.member.permissions.has(PermissionsBitField.Flags.ManageChannels) ||
      (config.ticketSupportRole && message.member.roles.cache.has(config.ticketSupportRole));

    if (command === "ticket-close") {
      if (ticket.ownerId !== message.author.id && !staff) {
        return reply(message, "No podés cerrar este ticket.", 0xE74C3C);
      }
      if (ticket.status === "closed") return reply(message, "Este ticket ya está cerrado.");
      await closeTicket(message.channel, message.author, config);
      return reply(message, "Ticket cerrado.");
    }

    if (command === "ticket-reopen") {
      if (!staff) return reply(message, "Solo soporte puede reabrir el ticket.", 0xE74C3C);
      await reopenTicket(message.channel, message.author, config);
      return reply(message, "Ticket reabierto.");
    }

    if (command === "ticket-add" || command === "ticket-remove") {
      if (!staff) return reply(message, "Solo soporte puede modificar participantes.", 0xE74C3C);
      const selected = message.mentions.users.first();
      if (!selected) return reply(message, `Uso: \`.${command} @usuario\`.`);

      const add = command === "ticket-add";
      await message.channel.permissionOverwrites.edit(selected.id, {
        ViewChannel: add,
        SendMessages: add,
        ReadMessageHistory: add
      }).then(() => reply(message, add ? "Usuario agregado." : "Usuario retirado."))
        .catch(() => reply(message, "No pude cambiar los permisos.", 0xE74C3C));
      return;
    }
  }
}

// ======================================
// AUTOMATIC PROTECTION
// ======================================

const recentMessages = new Map();
const joinHistory = new Map();

const phishingPatterns = [
  /discord[\W_]*nitro/i,
  /free[\W_]*nitro/i,
  /steam[\W_]*gift/i,
  /discord[\W_]*gift/i,
  /airdrop[\W_]*claim/i,
  /verify[\W_]*account/i
];

client.on("messageCreate", async message => {
  try {
    if (!message.guild || message.author.bot) return;

    if (message.content.startsWith(PREFIX)) {
      await prefixCommand(message);
      return;
    }

    const config = getServer(message.guild.id);
    const member = message.member;

    if (isWhitelisted(message.guild.id, message.author.id)) return;
    if (member.permissions.has(PermissionsBitField.Flags.ManageMessages)) return;

    const key = `${message.guild.id}:${message.author.id}`;
    const currentTime = Date.now();

    // Anti-phishing: heurística básica, puede generar falsos positivos.
    if (config.security.antiPhishing &&
        phishingPatterns.some(pattern => pattern.test(message.content))) {
      await message.delete().catch(() => {});
      await log(message.guild, "Posible phishing",
        `Mensaje sospechoso de <@${message.author.id}> en <#${message.channel.id}>.`,
        0xE74C3C);
      return;
    }

    // Anti mass mention.
    if (config.security.antiMentions &&
        (message.mentions.users.size >= 5 || message.mentions.everyone)) {
      await message.delete().catch(() => {});
      await log(message.guild, "Anti-Mass-Mention",
        `<@${message.author.id}> envió menciones masivas en <#${message.channel.id}>.`,
        0xE74C3C);
      return;
    }

    // Anti-spam / anti-flood.
    if (config.security.antiSpam || config.security.antiFlood) {
      const history = recentMessages.get(key) || [];
      history.push({
        content: message.content,
        time: currentTime
      });

      const recent = history.filter(item => currentTime - item.time < 7000);
      recentMessages.set(key, recent);

      const repeated = recent.filter(item => item.content === message.content).length >= 4;
      const flooding = recent.length >= 7;

      if ((config.security.antiSpam && repeated) ||
          (config.security.antiFlood && flooding)) {
        await message.delete().catch(() => {});

        await log(message.guild, "Anti-Spam / Anti-Flood",
          `Se detectó actividad repetitiva de <@${message.author.id}> en <#${message.channel.id}>.`,
          0xE74C3C);
      }
    }
  } catch (error) {
    console.error("Error en protecciones de mensajes:", error);
  }
});

// ======================================
// MESSAGE LOGS
// ======================================

client.on("messageDelete", async message => {
  try {
    if (!message.guild || message.author?.bot) return;

    const content = message.content || "Contenido no disponible";
    await log(message.guild, "Mensaje eliminado",
      `Autor: ${message.author ? `<@${message.author.id}>` : "Desconocido"}\nCanal: <#${message.channel.id}>\nContenido: ${content.slice(0, 1200)}`);
  } catch (error) {
    console.error("Error en messageDelete:", error);
  }
});

client.on("messageUpdate", async (oldMessage, newMessage) => {
  try {
    if (!newMessage.guild || newMessage.author?.bot) return;
    if (oldMessage.content === newMessage.content) return;

    await log(newMessage.guild, "Mensaje editado",
      `Autor: <@${newMessage.author.id}>\nCanal: <#${newMessage.channel.id}>\nAntes: ${(oldMessage.content || "No disponible").slice(0, 600)}\nDespués: ${(newMessage.content || "No disponible").slice(0, 600)}`);
  } catch (error) {
    console.error("Error en messageUpdate:", error);
  }
});

// ======================================
// MEMBER EVENTS
// ======================================

client.on("guildMemberAdd", async member => {
  try {
    const config = getServer(member.guild.id);

    if (config.welcome) {
      const channel = member.guild.channels.cache.get(config.welcome);
      if (channel?.isTextBased()) {
        await channel.send({
          embeds: [
            makeEmbed("¡Bienvenido/a!",
              `¡Hola ${member}! Bienvenido/a a **${member.guild.name}**.`)
          ]
        }).catch(() => {});
      }
    }

    if (config.autorole) {
      const role = member.guild.roles.cache.get(config.autorole);
      const botMember = await getBotMember(member.guild);

      if (role && botMember && role.position < botMember.roles.highest.position) {
        await member.roles.add(role).catch(error => {
          console.error("Error aplicando autorole:", error);
        });
      }
    }

    if (member.user.bot && config.security.antiBot &&
        !isWhitelisted(member.guild.id, member.id)) {
      if (await botHas(member.guild, PermissionsBitField.Flags.KickMembers)) {
        await member.kick("Bot no autorizado: Sentinel Security").catch(() => {});
      }

      await log(member.guild, "Anti-Bot",
        `Se detectó un bot no autorizado: ${member.user.tag}.`,
        0xE74C3C);
      return;
    }

    if (config.security.antiRaid) {
      const history = joinHistory.get(member.guild.id) || [];
      history.push(Date.now());

      const recent = history.filter(time => Date.now() - time < 10000);
      joinHistory.set(member.guild.id, recent);

      if (recent.length === 8) {
        await log(member.guild, "Posible Raid",
          `${recent.length} usuarios entraron en 10 segundos. Revisá el servidor.`,
          0xE74C3C);
      }
    }

    await log(member.guild, "Usuario entró",
      `${member.user.tag} (${member.id})`);
  } catch (error) {
    console.error("Error en guildMemberAdd:", error);
  }
});

client.on("guildMemberRemove", async member => {
  try {
    const config = getServer(member.guild.id);

    if (config.goodbye) {
      const channel = member.guild.channels.cache.get(config.goodbye);
      if (channel?.isTextBased()) {
        await channel.send({
          embeds: [
            makeEmbed("Hasta pronto",
              `**${member.user.tag}** salió del servidor.`)
          ]
        }).catch(() => {});
      }
    }

    await log(member.guild, "Usuario salió",
      `${member.user.tag} (${member.id})`);
  } catch (error) {
    console.error("Error en guildMemberRemove:", error);
  }
});

// ======================================
// WEBHOOK / ANTI-NUKE / ANTI-PERMISSION
// ======================================

client.on("webhookUpdate", async channel => {
  try {
    const config = getServer(channel.guild.id);
    if (!config.security.antiWebhook) return;

    await log(channel.guild, "Cambio de webhook",
      `Se detectó un cambio en los webhooks de <#${channel.id}>. Revisá los registros de auditoría.`,
      0xE74C3C);
  } catch (error) {
    console.error("Error en webhookUpdate:", error);
  }
});

const monitoredAuditEvents = [
  AuditLogEvent.ChannelDelete,
  AuditLogEvent.ChannelCreate,
  AuditLogEvent.RoleDelete,
  AuditLogEvent.RoleCreate,
  AuditLogEvent.RoleUpdate,
  AuditLogEvent.WebhookCreate,
  AuditLogEvent.WebhookDelete,
  AuditLogEvent.BotAdd,
  AuditLogEvent.MemberRoleUpdate
];

client.on("guildAuditLogEntryCreate", async (entry, guild) => {
  try {
    const config = getServer(guild.id);
    const executorId = entry.executorId;

    if (!executorId || isWhitelisted(guild.id, executorId)) return;

    const isDestructive = [
      AuditLogEvent.ChannelDelete,
      AuditLogEvent.RoleDelete,
      AuditLogEvent.WebhookCreate,
      AuditLogEvent.WebhookDelete,
      AuditLogEvent.BotAdd
    ].includes(entry.action);

    const isPermissionChange = [
      AuditLogEvent.RoleCreate,
      AuditLogEvent.RoleUpdate,
      AuditLogEvent.MemberRoleUpdate,
      AuditLogEvent.ChannelCreate
    ].includes(entry.action);

    if (config.security.antiNuke && isDestructive) {
      await log(guild, "Alerta Anti-Nuke",
        `Acción detectada: **${entry.action}**\nResponsable: <@${executorId}>.\nRevisá los registros de auditoría.`,
        0xE74C3C);
    }

    if (config.security.antiPermission && isPermissionChange) {
      await log(guild, "Alerta Anti-Permission",
        `Cambio de permisos o estructura detectado.\nAcción: **${entry.action}**\nResponsable: <@${executorId}>.`,
        0xE74C3C);
    }
  } catch (error) {
    console.error("Error en auditoría:", error);
  }
});

// ======================================
// INTERACTIONS: SLASH AND BUTTONS
// ======================================

client.on("interactionCreate", async interaction => {
  try {
    if (interaction.isChatInputCommand()) {
      // Responder a Discord dentro del límite de 3 segundos.
      await interaction.deferReply({ ephemeral: true });
      await slashCommand(interaction);
      return;
    }

    if (!interaction.isButton()) return;
    if (!interaction.guild) {
      return interaction.reply({
        content: "Este botón solo funciona dentro de un servidor.",
        ephemeral: true
      });
    }

    await interaction.deferReply({ ephemeral: true });

    if (interaction.customId === "sentinel_ticket_create") {
      return createTicket(interaction);
    }

    const config = getServer(interaction.guild.id);
    const ticket = config.tickets[interaction.channel.id];

    if (interaction.customId === "sentinel_ticket_close") {
      if (!ticket) return reply(interaction, "Este canal no está registrado como ticket.");

      const staff = isTicketStaff(interaction, config);
      const owner = ticket.ownerId === interaction.user.id;

      if (!owner && !staff) {
        return reply(interaction, "No podés cerrar este ticket.", 0xE74C3C);
      }

      if (ticket.status === "closed") {
        return reply(interaction, "Este ticket ya está cerrado.");
      }

      await closeTicket(interaction.channel, interaction.user, config);
      return reply(interaction, "Ticket cerrado correctamente.");
    }

    if (interaction.customId === "sentinel_ticket_reopen") {
      if (!ticket) return reply(interaction, "Este canal no está registrado como ticket.");

      if (!isTicketStaff(interaction, config)) {
        return reply(interaction, "Solo el equipo de soporte puede reabrirlo.", 0xE74C3C);
      }

      if (ticket.status === "open") {
        return reply(interaction, "Este ticket ya está abierto.");
      }

      await reopenTicket(interaction.channel, interaction.user, config);
      return reply(interaction, "Ticket reabierto.");
    }
  } catch (error) {
    console.error("Error en interacción:", error);

    if (interaction.isRepliable()) {
      if (interaction.deferred || interaction.replied) {
        await interaction.followUp({
          content: "Ocurrió un error al procesar la acción.",
          ephemeral: true
        }).catch(() => {});
      } else {
        await interaction.reply({
          content: "Ocurrió un error al procesar la acción.",
          ephemeral: true
        }).catch(() => {});
      }
    }
  }
});

// ======================================
// PRESENCE AND COMMAND REGISTRATION
// ======================================

function updatePresence() {
  if (!client.user) return;

  client.user.setActivity(
    `Observando ${client.guilds.cache.size} servidores`,
    { type: ActivityType.Watching }
  );
}

client.once("ready", async () => {
  console.log(`Sentinel Security conectado como ${client.user.tag}`);

  updatePresence();

  const rest = new REST({ version: "10" }).setToken(TOKEN);

  try {
    await rest.put(
      Routes.applicationCommands(CLIENT_ID),
      { body: commands.map(command => command.toJSON()) }
    );

    console.log(`Se registraron ${commands.length} comandos slash.`);
  } catch (error) {
    console.error("Error registrando comandos slash:", error);
  }
});

client.on("guildCreate", updatePresence);
client.on("guildDelete", updatePresence);

client.on("error", error => {
  console.error("Error del cliente Discord:", error);
});

process.on("unhandledRejection", error => {
  console.error("Promesa no controlada:", error);
});

client.login(TOKEN);
