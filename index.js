
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

// =====================================
// SENTINEL SECURITY
// =====================================

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
    GatewayIntentBits.GuildWebhooks,
    GatewayIntentBits.GuildMessageReactions
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
  warnings: {},
  notes: {},
  cases: [],
  whitelist: [],
  security: {
    antiRaid: false,
    antiSpam: false,
    antiFlood: false,
    antiMentions: false,
    antiPhishing: false,
    antiWebhook: false,
    antiNuke: false,
    antiBot: false,
    lockdown: false
  },
  counters: {
    joins: [],
    messages: {},
    mentions: {},
    actions: {}
  }
});

function loadData() {
  try {
    if (!fs.existsSync(FILE)) {
      fs.writeFileSync(FILE, JSON.stringify({ servers: {} }, null, 2));
    }

    const parsed = JSON.parse(fs.readFileSync(FILE, "utf8"));

    if (!parsed.servers) parsed.servers = {};
    return parsed;
  } catch (error) {
    console.error("Error leyendo data.json:", error);
    return { servers: {} };
  }
}

let data = loadData();

function saveData() {
  fs.writeFileSync(FILE, JSON.stringify(data, null, 2));
}

function getServer(guildId) {
  if (!data.servers[guildId]) {
    data.servers[guildId] = defaultServer();
  }

  const current = data.servers[guildId];

  // Compatibilidad con configuraciones antiguas
  const defaults = defaultServer();

  for (const key of Object.keys(defaults)) {
    if (current[key] === undefined) current[key] = defaults[key];
  }

  for (const key of Object.keys(defaults.security)) {
    if (current.security[key] === undefined) {
      current.security[key] = defaults.security[key];
    }
  }

  return current;
}

function now() {
  const unix = Math.floor(Date.now() / 1000);
  return {
    unix,
    full: `<t:${unix}:F>`,
    relative: `<t:${unix}:R>`
  };
}

function embed(title, description, color = 0x1677FF) {
  const time = now();

  return new EmbedBuilder()
    .setColor(color)
    .setTitle(`🛡️ ${title}`)
    .setDescription(description || "Sin información.")
    .addFields({
      name: "Fecha y hora",
      value: `${time.full}\n${time.relative}`,
      inline: false
    })
    .setFooter({ text: "Sentinel Security" })
    .setTimestamp();
}

async function reply(ctx, message, color = 0x1677FF) {
  const e = embed("Sentinel Security", message, color);

  if (ctx.isChatInputCommand?.()) {
    if (ctx.replied || ctx.deferred) {
      return ctx.followUp({ embeds: [e], ephemeral: true });
    }
    return ctx.reply({ embeds: [e], ephemeral: true });
  }

  return ctx.reply({ embeds: [e] });
}

async function log(guild, title, description, color = 0x1677FF) {
  const config = getServer(guild.id);
  if (!config.logs) return;

  const channel = guild.channels.cache.get(config.logs);
  if (!channel || !channel.isTextBased()) return;

  await channel.send({
    embeds: [embed(title, description, color)]
  }).catch(() => {});
}

function hasPermission(member, permission) {
  return member?.permissions?.has(permission) ?? false;
}

function isWhitelisted(guildId, userId) {
  return getServer(guildId).whitelist.includes(userId);
}

async function getMember(guild, input) {
  if (!input) return null;

  const id = input.replace(/[<@!>]/g, "");
  if (!/^\d{17,20}$/.test(id)) return null;

  return guild.members.fetch(id).catch(() => null);
}

function canManageTarget(actor, target) {
  if (!actor || !target) return false;
  if (target.id === actor.id) return false;
  if (target.id === actor.guild.ownerId) return false;
  if (actor.id === actor.guild.ownerId) return true;

  return actor.roles.highest.comparePositionTo(target.roles.highest) > 0;
}

async function botHas(guild, permission) {
  const me = guild.members.me ||
    await guild.members.fetch(client.user.id).catch(() => null);

  return me?.permissions.has(permission) ?? false;
}

async function requirePermission(ctx, permission) {
  const member = ctx.member;

  if (!hasPermission(member, permission)) {
    await reply(ctx, "No tenés permiso para ejecutar esta acción.", 0xE74C3C);
    return false;
  }

  return true;
}

async function requireBotPermission(ctx, permission) {
  if (!await botHas(ctx.guild, permission)) {
    await reply(ctx, `Me falta el permiso: **${permission}**.`, 0xE74C3C);
    return false;
  }

  return true;
}

function addCase(guildId, entry) {
  const config = getServer(guildId);

  config.cases.push({
    id: config.cases.length + 1,
    ...entry,
    date: new Date().toISOString()
  });

  if (config.cases.length > 500) {
    config.cases.shift();
  }

  saveData();
}

// =====================================
// SLASH COMMANDS
// =====================================

const commands = [
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
    .setDescription("Advertir un usuario")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true))
    .addStringOption(o => o.setName("motivo").setDescription("Motivo").setRequired(true)),

  new SlashCommandBuilder()
    .setName("unwarn")
    .setDescription("Quitar una advertencia")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true))
    .addIntegerOption(o => o.setName("numero").setDescription("Número de advertencia").setRequired(true)),

  new SlashCommandBuilder()
    .setName("warnings")
    .setDescription("Ver advertencias")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true)),

  new SlashCommandBuilder()
    .setName("purge")
    .setDescription("Eliminar mensajes")
    .addIntegerOption(o => o.setName("cantidad").setDescription("Cantidad (1-100)").setRequired(true).setMinValue(1).setMaxValue(100)),

  new SlashCommandBuilder()
    .setName("slowmode")
    .setDescription("Configurar slowmode")
    .addIntegerOption(o => o.setName("segundos").setDescription("0 a 21600").setRequired(true).setMinValue(0).setMaxValue(21600)),

  new SlashCommandBuilder()
    .setName("lock")
    .setDescription("Bloquear canal"),

  new SlashCommandBuilder()
    .setName("unlock")
    .setDescription("Desbloquear canal"),

  new SlashCommandBuilder()
    .setName("role")
    .setDescription("Agregar o quitar un rol")
    .addStringOption(o => o.setName("accion").setDescription("add o remove").setRequired(true).addChoices(
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
    .addChannelOption(o => o.setName("canal").setDescription("Canal de registros").setRequired(true)),

  new SlashCommandBuilder()
    .setName("note")
    .setDescription("Agregar una nota")
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true))
    .addStringOption(o => o.setName("texto").setDescription("Nota").setRequired(true)),

  new SlashCommandBuilder()
    .setName("security")
    .setDescription("Consultar o configurar protecciones")
    .addStringOption(o => o.setName("proteccion").setDescription("Protección").setRequired(true).addChoices(
      { name: "Anti-Raid", value: "antiRaid" },
      { name: "Anti-Spam", value: "antiSpam" },
      { name: "Anti-Flood", value: "antiFlood" },
      { name: "Anti-Menciones", value: "antiMentions" },
      { name: "Anti-Phishing", value: "antiPhishing" },
      { name: "Anti-Webhook", value: "antiWebhook" },
      { name: "Anti-Nuke", value: "antiNuke" },
      { name: "Anti-Bot", value: "antiBot" }
    ))
    .addBooleanOption(o => o.setName("activar").setDescription("Activar o desactivar").setRequired(true)),

  new SlashCommandBuilder()
    .setName("security-status")
    .setDescription("Ver estado de seguridad"),

  new SlashCommandBuilder()
    .setName("whitelist")
    .setDescription("Administrar lista de confianza")
    .addStringOption(o => o.setName("accion").setDescription("add o remove").setRequired(true).addChoices(
      { name: "Agregar", value: "add" },
      { name: "Quitar", value: "remove" }
    ))
    .addUserOption(o => o.setName("usuario").setDescription("Usuario").setRequired(true)),

  new SlashCommandBuilder()
    .setName("lockdown")
    .setDescription("Activar bloqueo de emergencia"),

  new SlashCommandBuilder()
    .setName("unlockdown")
    .setDescription("Desactivar bloqueo de emergencia"),

  new SlashCommandBuilder()
    .setName("welcome")
    .setDescription("Configurar bienvenida")
    .addChannelOption(o => o.setName("canal").setDescription("Canal").setRequired(true)),

  new SlashCommandBuilder()
    .setName("goodbye")
    .setDescription("Configurar despedidas")
    .addChannelOption(o => o.setName("canal").setDescription("Canal").setRequired(true)),

  new SlashCommandBuilder()
    .setName("autorole")
    .setDescription("Configurar rol automático")
    .addRoleOption(o => o.setName("rol").setDescription("Rol").setRequired(true)),

  new SlashCommandBuilder()
    .setName("ticket-setup")
    .setDescription("Crear panel de tickets")
    .addChannelOption(o => o.setName("categoria").setDescription("Categoría de tickets").setRequired(true)),

  new SlashCommandBuilder()
    .setName("ticket-close")
    .setDescription("Cerrar ticket"),

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
    .addStringOption(o => o.setName("idioma").setDescription("Idioma").setRequired(true).addChoices(
      { name: "Español", value: "es" },
      { name: "English", value: "en" }
    ))
];

// =====================================
// COMMAND HELPERS
// =====================================

async function moderate(ctx, action, target, reason = "Sin motivo") {
  const guild = ctx.guild;
  const actor = await guild.members.fetch(ctx.user?.id || ctx.author.id);
  const member = await guild.members.fetch(target.id).catch(() => null);

  if (member && !canManageTarget(actor, member)) {
    return reply(ctx, "No podés moderar a alguien con un rol igual o superior al tuyo.", 0xE74C3C);
  }

  if (member && !canManageTarget(guild.members.me, member)) {
    return reply(ctx, "Mi rol está por debajo del usuario afectado.", 0xE74C3C);
  }

  try {
    if (action === "ban") {
      await guild.members.ban(target.id, { reason });
    }

    if (action === "kick") {
      if (!member) return reply(ctx, "Ese usuario no está en el servidor.", 0xE74C3C);
      await member.kick(reason);
    }

    const entry = {
      action,
      user: target.id,
      moderator: actor.id,
      reason
    };

    addCase(guild.id, entry);
    await log(guild, `Moderación: ${action}`, `Usuario: <@${target.id}>\nModerador: <@${actor.id}>\nMotivo: ${reason}`);

    return reply(ctx, `Acción **${action}** realizada sobre <@${target.id}>.\nMotivo: ${reason}`);
  } catch (error) {
    console.error(error);
    return reply(ctx, "No pude realizar la acción. Revisá mis permisos y la jerarquía de roles.", 0xE74C3C);
  }
}

// =====================================
// PREFIX COMMANDS
// =====================================

async function prefixCommand(message) {
  if (!message.guild || message.author.bot) return;

  const args = message.content.slice(PREFIX.length).trim().split(/\s+/);
  const command = (args.shift() || "").toLowerCase();

  if (!command) return;

  const config = getServer(message.guild.id);
  const actor = message.member;

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
    "ticket-add": PermissionsBitField.Flags.ManageChannels,
    "ticket-remove": PermissionsBitField.Flags.ManageChannels,
    language: PermissionsBitField.Flags.ManageGuild,
    history: PermissionsBitField.Flags.ViewAuditLog
  };

  if (permissions[command] && !hasPermission(actor, permissions[command])) {
    return reply(message, "No tenés permiso para ese comando.", 0xE74C3C);
  }

  const target = await getMember(message.guild, args[0]);
  const reason = args.slice(1).join(" ") || "Sin motivo";

  if (["ban", "kick"].includes(command)) {
    if (!target) return reply(message, "Indicá un usuario válido.");
    return moderate(message, command, target.user, reason);
  }

  if (command === "unban") {
    if (!args[0]) return reply(message, "Uso: `.unban ID`");
    if (!await requireBotPermission(message, PermissionsBitField.Flags.BanMembers)) return;
    try {
      await message.guild.members.unban(args[0], reason);
      addCase(message.guild.id, {
        action: "unban",
        user: args[0],
        moderator: message.author.id,
        reason
      });
      return reply(message, "Usuario desbaneado correctamente.");
    } catch {
      return reply(message, "No pude desbanear ese ID.", 0xE74C3C);
    }
  }

  if (command === "timeout") {
    if (!target || !args[1]) return reply(message, "Uso: `.timeout @usuario minutos motivo`");
    if (!await requireBotPermission(message, PermissionsBitField.Flags.ModerateMembers)) return;
    if (!canManageTarget(actor, target) || !canManageTarget(message.guild.members.me, target)) {
      return reply(message, "No podés aplicar timeout a ese usuario.", 0xE74C3C);
    }

    const minutes = Number(args[1]);
    if (!Number.isInteger(minutes) || minutes < 1 || minutes > 40320) {
      return reply(message, "La duración debe ser de 1 a 40320 minutos.");
    }

    await target.timeout(minutes * 60000, args.slice(2).join(" ") || "Sin motivo")
      .then(() => reply(message, `Timeout aplicado a <@${target.id}> por ${minutes} minutos.`))
      .catch(() => reply(message, "No pude aplicar el timeout.", 0xE74C3C));
    return;
  }

  if (command === "untimeout") {
    if (!target) return reply(message, "Uso: `.untimeout @usuario`");
    if (!await requireBotPermission(message, PermissionsBitField.Flags.ModerateMembers)) return;
    if (!canManageTarget(actor, target) || !canManageTarget(message.guild.members.me, target)) {
      return reply(message, "No podés modificar a ese usuario.", 0xE74C3C);
    }

    await target.timeout(null)
      .then(() => reply(message, "Timeout eliminado."))
      .catch(() => reply(message, "No pude quitar el timeout.", 0xE74C3C));
    return;
  }

  if (command === "warn") {
    if (!target || !args[1]) return reply(message, "Uso: `.warn @usuario motivo`");
    config.warnings[target.id] ??= [];
    config.warnings[target.id].push({
      moderator: message.author.id,
      reason: args.slice(1).join(" "),
      date: new Date().toISOString()
    });
    addCase(message.guild.id, {
      action: "warn",
      user: target.id,
      moderator: message.author.id,
      reason: args.slice(1).join(" ")
    });
    saveData();
    await log(message.guild, "Advertencia", `<@${target.id}> recibió una advertencia de <@${message.author.id}>.`);
    return reply(message, `Advertencia registrada para <@${target.id}>.`);
  }

  if (command === "warnings") {
    if (!target) return reply(message, "Uso: `.warnings @usuario`");
    const warnings = config.warnings[target.id] || [];
    return reply(message, warnings.length
      ? warnings.map((w, i) => `**${i + 1}.** ${w.reason} — <t:${Math.floor(new Date(w.date).getTime() / 1000)}:R>`).join("\n")
      : "Este usuario no tiene advertencias.");
  }

  if (command === "unwarn") {
    if (!target || !args[1]) return reply(message, "Uso: `.unwarn @usuario número`");
    const warnings = config.warnings[target.id] || [];
    const index = Number(args[1]) - 1;
    if (!Number.isInteger(index) || index < 0 || index >= warnings.length) {
      return reply(message, "Número de advertencia no válido.");
    }
    warnings.splice(index, 1);
    saveData();
    return reply(message, "Advertencia eliminada.");
  }

  if (command === "purge") {
    const amount = Number(args[0]);
    if (!Number.isInteger(amount) || amount < 1 || amount > 100) {
      return reply(message, "Uso: `.purge 1-100`");
    }
    if (!await requireBotPermission(message, PermissionsBitField.Flags.ManageMessages)) return;
    const deleted = await message.channel.bulkDelete(amount, true).catch(() => null);
    return reply(message, deleted ? `Eliminé ${deleted.size} mensajes.` : "No pude eliminar los mensajes.");
  }

  if (command === "slowmode") {
    const seconds = Number(args[0]);
    if (!Number.isInteger(seconds) || seconds < 0 || seconds > 21600) {
      return reply(message, "Uso: `.slowmode 0-21600`");
    }
    await message.channel.setRateLimitPerUser(seconds)
      .then(() => reply(message, `Slowmode configurado en ${seconds} segundos.`))
      .catch(() => reply(message, "No pude cambiar el slowmode."));
    return;
  }

  if (command === "lock" || command === "unlock") {
    const me = message.guild.members.me;
    if (!me.permissionsIn(message.channel).has(PermissionsBitField.Flags.ManageChannels)) {
      return reply(message, "Me falta Manage Channels.", 0xE74C3C);
    }
    const everyone = message.guild.roles.everyone;
    const value = command === "lock" ? false : null;
    await message.channel.permissionOverwrites.edit(everyone, {
      SendMessages: value
    }).then(() => reply(message, command === "lock" ? "Canal bloqueado." : "Canal desbloqueado."))
      .catch(() => reply(message, "No pude modificar el canal."));
    return;
  }

  if (command === "role") {
    const action = args[0];
    const member = await getMember(message.guild, args[1]);
    const roleId = args[2]?.replace(/[<@&>]/g, "");
    const role = message.guild.roles.cache.get(roleId);

    if (!["add", "remove"].includes(action) || !member || !role) {
      return reply(message, "Uso: `.role add/remove @usuario @rol`");
    }

    if (!canManageTarget(actor, member) ||
        !canManageTarget(message.guild.members.me, member) ||
        role.position >= message.guild.members.me.roles.highest.position ||
        role.position >= actor.roles.highest.position && actor.id !== message.guild.ownerId) {
      return reply(message, "No podés modificar ese usuario o rol por jerarquía.", 0xE74C3C);
    }

    await member.roles[action === "add" ? "add" : "remove"](role)
      .then(() => reply(message, "Rol actualizado."))
      .catch(() => reply(message, "No pude modificar el rol."));
    return;
  }

  if (command === "modlogs") {
    const channel = message.mentions.channels.first();
    if (!channel) return reply(message, "Uso: `.modlogs #canal`");
    config.logs = channel.id;
    saveData();
    return reply(message, "Canal de registros configurado.");
  }

  if (command === "security") {
    const key = args[0];
    const value = args[1]?.toLowerCase();
    if (!Object.hasOwn(config.security, key) || key === "lockdown") {
      return reply(message, "Protecciones: antiRaid, antiSpam, antiFlood, antiMentions, antiPhishing, antiWebhook, antiNuke, antiBot.");
    }
    if (!["on", "off"].includes(value)) return reply(message, "Uso: `.security antiSpam on/off`");
    config.security[key] = value === "on";
    saveData();
    return reply(message, `${key}: ${value}`);
  }

  if (command === "security-status") {
    return reply(message, Object.entries(config.security)
      .map(([key, value]) => `**${key}:** ${value ? "Activado" : "Desactivado"}`).join("\n"));
  }

  if (command === "whitelist") {
    const action = args[0];
    const id = args[1]?.replace(/[<@!>]/g, "");
    if (!["add", "remove"].includes(action) || !id) return reply(message, "Uso: `.whitelist add/remove ID`");
    if (action === "add" && !config.whitelist.includes(id)) config.whitelist.push(id);
    if (action === "remove") config.whitelist = config.whitelist.filter(x => x !== id);
    saveData();
    return reply(message, "Lista de confianza actualizada.");
  }

  if (command === "language") {
    if (!["es", "en"].includes(args[0])) return reply(message, "Uso: `.language es/en`");
    config.language = args[0];
    saveData();
    return reply(message, `Idioma configurado: ${args[0]}`);
  }

  if (command === "welcome" || command === "goodbye") {
    const channel = message.mentions.channels.first();
    if (!channel) return reply(message, `Uso: \`.${command} #canal\``);
    config[command] = channel.id;
    saveData();
    return reply(message, `Canal de ${command} configurado.`);
  }

  if (command === "autorole") {
    const role = message.mentions.roles.first();
    if (!role) return reply(message, "Uso: `.autorole @rol`");
    if (role.position >= message.guild.members.me.roles.highest.position) {
      return reply(message, "Mi rol debe estar por encima del rol automático.");
    }
    config.autorole = role.id;
    saveData();
    return reply(message, "Autorole configurado.");
  }

  if (command === "note") {
    if (!target || !args[1]) return reply(message, "Uso: `.note @usuario texto`");
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
    if (!id) return reply(message, "Uso: `.history @usuario`");
    const cases = config.cases.filter(c => c.user === id).slice(-10);
    return reply(message, cases.length
      ? cases.map(c => `**${c.action}** — ${c.reason} — <t:${Math.floor(new Date(c.date).getTime() / 1000)}:R>`).join("\n")
      : "No hay registros para ese usuario.");
  }

  if (command === "lockdown" || command === "unlockdown") {
    return setLockdown(message.guild, command === "lockdown", message);
  }

  if (command === "ticket-setup") {
    const category = message.mentions.channels.first();
    if (!category || category.type !== ChannelType.GuildCategory) {
      return reply(message, "Uso: `.ticket-setup #categoría`");
    }

    config.ticketCategory = category.id;
    saveData();

    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId("sentinel_ticket_create")
        .setLabel("Crear ticket")
        .setEmoji("🎫")
        .setStyle(ButtonStyle.Primary)
    );

    await message.channel.send({
      embeds: [embed("Soporte", "Presioná el botón para crear un ticket.")],
      components: [row]
    });

    return reply(message, "Panel de tickets creado.");
  }

  if (command === "ticket-close") {
    if (!message.channel.name.startsWith("ticket-")) return reply(message, "Este canal no parece ser un ticket.");
    await message.channel.delete("Ticket cerrado").catch(() => {});
    return;
  }

  if (command === "ticket-add" || command === "ticket-remove") {
    if (!message.channel.name.startsWith("ticket-")) return reply(message, "Este canal no parece ser un ticket.");
    const user = message.mentions.users.first();
    if (!user) return reply(message, `Uso: \`.${command} @usuario\``);
    await message.channel.permissionOverwrites.edit(user.id, {
      ViewChannel: command === "ticket-add",
      SendMessages: command === "ticket-add"
    }).then(() => reply(message, "Permisos del ticket actualizados."))
      .catch(() => reply(message, "No pude actualizar los permisos."));
    return;
  }

  if (command === "help") {
    return reply(message,
      "**Moderación:** ban, unban, kick, timeout, untimeout, warn, unwarn, warnings, purge, slowmode, lock, unlock, role, nickname\n\n" +
      "**Seguridad:** security, security-status, whitelist, lockdown, unlockdown\n\n" +
      "**Administración:** modlogs, welcome, goodbye, autorole, ticket-setup, ticket-close, ticket-add, ticket-remove, language, note, history\n\n" +
      "También podés usar los comandos slash `/`."
    );
  }
}

// =====================================
// LOCKDOWN
// =====================================

async function setLockdown(guild, enabled, ctx) {
  const config = getServer(guild.id);

  if (!hasPermission(ctx.member, PermissionsBitField.Flags.Administrator) &&
      !hasPermission(ctx.member, PermissionsBitField.Flags.ManageChannels)) {
    return reply(ctx, "Necesitás Administrador o Manage Channels.", 0xE74C3C);
  }

  if (enabled) {
    config.security.lockdown = true;
    saveData();

    for (const channel of guild.channels.cache.values()) {
      if (!channel.isTextBased() || !channel.permissionOverwrites) continue;

      await channel.permissionOverwrites.edit(guild.roles.everyone, {
        SendMessages: false
      }).catch(() => {});
    }

    await log(guild, "Bloqueo de emergencia", `Activado por <@${ctx.user?.id || ctx.author.id}>`, 0xE74C3C);
    return reply(ctx, "Bloqueo de emergencia activado.", 0xE74C3C);
  }

  config.security.lockdown = false;
  saveData();

  // No se restauran permisos automáticamente: podrían sobrescribir
  // permisos que un administrador haya cambiado durante el bloqueo.
  await log(guild, "Bloqueo de emergencia", `Desactivado por <@${ctx.user?.id || ctx.author.id}>`);
  return reply(ctx, "Modo de emergencia desactivado. Revisá los permisos de los canales y restauralos según corresponda.");
}

// =====================================
// SLASH HANDLER
// =====================================

async function slashCommand(interaction) {
  const guild = interaction.guild;
  const config = getServer(guild.id);
  const name = interaction.commandName;
  const user = interaction.user;
  const actor = await guild.members.fetch(user.id).catch(() => null);

  const permissionMap = {
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
    "ticket-add": PermissionsBitField.Flags.ManageChannels,
    "ticket-remove": PermissionsBitField.Flags.ManageChannels,
    language: PermissionsBitField.Flags.ManageGuild,
    history: PermissionsBitField.Flags.ViewAuditLog
  };

  if (permissionMap[name] && !hasPermission(actor, permissionMap[name])) {
    return reply(interaction, "No tenés permiso para este comando.", 0xE74C3C);
  }

  const target = interaction.options.getUser("usuario");
  const member = target
    ? await guild.members.fetch(target.id).catch(() => null)
    : null;

  const reason = interaction.options.getString("motivo") || "Sin motivo";

  if (["ban", "kick"].includes(name)) {
    if (!await requireBotPermission(interaction,
      name === "ban" ? PermissionsBitField.Flags.BanMembers : PermissionsBitField.Flags.KickMembers)) return;
    if (!target) return;
    return moderate(interaction, name, target, reason);
  }

  if (name === "unban") {
    if (!await requireBotPermission(interaction, PermissionsBitField.Flags.BanMembers)) return;
    const id = interaction.options.getString("id");
    try {
      await guild.members.unban(id, "Unban solicitado por moderador");
      addCase(guild.id, { action: "unban", user: id, moderator: user.id, reason });
      return reply(interaction, "Usuario desbaneado.");
    } catch {
      return reply(interaction, "No pude desbanear ese ID.", 0xE74C3C);
    }
  }

  if (name === "timeout" || name === "untimeout") {
    if (!member) return reply(interaction, "El usuario no está en este servidor.");
    if (!await requireBotPermission(interaction, PermissionsBitField.Flags.ModerateMembers)) return;
    if (!canManageTarget(actor, member) || !canManageTarget(guild.members.me, member)) {
      return reply(interaction, "No podés modificar a ese usuario por jerarquía.", 0xE74C3C);
    }

    try {
      if (name === "timeout") {
        const minutes = interaction.options.getInteger("minutos");
        await member.timeout(minutes * 60000, reason);
        addCase(guild.id, { action: "timeout", user: target.id, moderator: user.id, reason });
        return reply(interaction, `Timeout aplicado durante ${minutes} minutos.`);
      }

      await member.timeout(null);
      addCase(guild.id, { action: "untimeout", user: target.id, moderator: user.id, reason });
      return reply(interaction, "Timeout eliminado.");
    } catch {
      return reply(interaction, "No pude aplicar esa acción.", 0xE74C3C);
    }
  }

  if (name === "warn") {
    config.warnings[target.id] ??= [];
    config.warnings[target.id].push({
      moderator: user.id,
      reason,
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
    if (index < 0 || index >= warnings.length) return reply(interaction, "Número no válido.");
    warnings.splice(index, 1);
    saveData();
    return reply(interaction, "Advertencia eliminada.");
  }

  if (name === "purge") {
    if (!await requireBotPermission(interaction, PermissionsBitField.Flags.ManageMessages)) return;
    const amount = interaction.options.getInteger("cantidad");
    const deleted = await interaction.channel.bulkDelete(amount, true).catch(() => null);
    return reply(interaction, deleted ? `Eliminé ${deleted.size} mensajes.` : "No pude eliminar los mensajes.");
  }

  if (name === "slowmode") {
    const seconds = interaction.options.getInteger("segundos");
    await interaction.channel.setRateLimitPerUser(seconds)
      .then(() => reply(interaction, `Slowmode configurado en ${seconds} segundos.`))
      .catch(() => reply(interaction, "No pude cambiar el slowmode."));
    return;
  }

  if (name === "lock" || name === "unlock") {
    const value = name === "lock" ? false : null;
    await interaction.channel.permissionOverwrites.edit(guild.roles.everyone, {
      SendMessages: value
    }).then(() => reply(interaction, name === "lock" ? "Canal bloqueado." : "Canal desbloqueado."))
      .catch(() => reply(interaction, "No pude modificar el canal."));
    return;
  }

  if (name === "role") {
    const action = interaction.options.getString("accion");
    const role = interaction.options.getRole("rol");

    if (!member || !role) return reply(interaction, "Usuario o rol no válido.");
    if (!canManageTarget(actor, member) ||
        !canManageTarget(guild.members.me, member) ||
        role.position >= guild.members.me.roles.highest.position ||
        (role.position >= actor.roles.highest.position && actor.id !== guild.ownerId)) {
      return reply(interaction, "No podés modificar ese usuario o rol por jerarquía.", 0xE74C3C);
    }

    await member.roles[action === "add" ? "add" : "remove"](role)
      .then(() => reply(interaction, "Rol actualizado."))
      .catch(() => reply(interaction, "No pude modificar el rol."));
    return;
  }

  if (name === "nickname") {
    const nickname = interaction.options.getString("nombre");
    if (!member || !canManageTarget(actor, member) || !canManageTarget(guild.members.me, member)) {
      return reply(interaction, "No podés cambiar el apodo de ese usuario.", 0xE74C3C);
    }
    await member.setNickname(nickname)
      .then(() => reply(interaction, "Apodo actualizado."))
      .catch(() => reply(interaction, "No pude cambiar el apodo."));
    return;
  }

  if (name === "modlogs") {
    const channel = interaction.options.getChannel("canal");
    if (channel.type !== ChannelType.GuildText) return reply(interaction, "Elegí un canal de texto.");
    config.logs = channel.id;
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

  if (name === "history") {
    const cases = config.cases.filter(c => c.user === target.id).slice(-10);
    return reply(interaction, cases.length
      ? cases.map(c => `**${c.action}** — ${c.reason} — <t:${Math.floor(new Date(c.date).getTime() / 1000)}:R>`).join("\n")
      : "No hay registros para este usuario.");
  }

  if (name === "security") {
    const key = interaction.options.getString("proteccion");
    const enabled = interaction.options.getBoolean("activar");
    config.security[key] = enabled;
    saveData();
    return reply(interaction, `${key}: ${enabled ? "Activado" : "Desactivado"}`);
  }

  if (name === "security-status") {
    return reply(interaction, Object.entries(config.security)
      .map(([key, value]) => `**${key}:** ${value ? "Activado" : "Desactivado"}`).join("\n"));
  }

  if (name === "whitelist") {
    const action = interaction.options.getString("accion");
    const id = target.id;

    if (action === "add" && !config.whitelist.includes(id)) config.whitelist.push(id);
    if (action === "remove") config.whitelist = config.whitelist.filter(x => x !== id);

    saveData();
    return reply(interaction, "Lista de confianza actualizada.");
  }

  if (name === "lockdown" || name === "unlockdown") {
    return setLockdown(guild, name === "lockdown", interaction);
  }

  if (name === "welcome" || name === "goodbye") {
    const channel = interaction.options.getChannel("canal");
    if (channel.type !== ChannelType.GuildText) return reply(interaction, "Elegí un canal de texto.");
    config[name] = channel.id;
    saveData();
    return reply(interaction, `Canal de ${name} configurado.`);
  }

  if (name === "autorole") {
    const role = interaction.options.getRole("rol");
    if (role.position >= guild.members.me.roles.highest.position) {
      return reply(interaction, "Mi rol debe estar por encima del rol automático.");
    }
    config.autorole = role.id;
    saveData();
    return reply(interaction, "Autorole configurado.");
  }

  if (name === "ticket-setup") {
    const category = interaction.options.getChannel("categoria");
    if (category.type !== ChannelType.GuildCategory) return reply(interaction, "Elegí una categoría.");

    config.ticketCategory = category.id;
    saveData();

    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId("sentinel_ticket_create")
        .setLabel("Crear ticket")
        .setEmoji("🎫")
        .setStyle(ButtonStyle.Primary)
    );

    await interaction.channel.send({
      embeds: [embed("Soporte", "Presioná el botón para crear un ticket.")],
      components: [row]
    });

    return reply(interaction, "Panel de tickets creado.");
  }

  if (name === "ticket-close") {
    if (!interaction.channel.name.startsWith("ticket-")) return reply(interaction, "Este canal no parece ser un ticket.");
    await reply(interaction, "Cerrando ticket...");
    await interaction.channel.delete("Ticket cerrado").catch(() => {});
    return;
  }

  if (name === "ticket-add" || name === "ticket-remove") {
    if (!interaction.channel.name.startsWith("ticket-")) return reply(interaction, "Este canal no parece ser un ticket.");
    const selected = interaction.options.getUser("usuario");

    await interaction.channel.permissionOverwrites.edit(selected.id, {
      ViewChannel: name === "ticket-add",
      SendMessages: name === "ticket-add"
    }).then(() => reply(interaction, "Permisos actualizados."))
      .catch(() => reply(interaction, "No pude actualizar los permisos."));
    return;
  }

  if (name === "language") {
    config.language = interaction.options.getString("idioma");
    saveData();
    return reply(interaction, `Idioma configurado: ${config.language}`);
  }
}

// =====================================
// AUTOMATIC SECURITY
// =====================================

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
  if (!message.guild || message.author.bot) return;

  const config = getServer(message.guild.id);

  if (message.content.startsWith(PREFIX)) {
    await prefixCommand(message);
    return;
  }

  if (isWhitelisted(message.guild.id, message.author.id)) return;

  const member = message.member;
  const nowTime = Date.now();
  const key = `${message.guild.id}:${message.author.id}`;

  // Anti-phishing: detección heurística, no garantiza detectar todos los enlaces
  if (config.security.antiPhishing) {
    const suspicious = phishingPatterns.some(pattern => pattern.test(message.content));

    if (suspicious && !member.permissions.has(PermissionsBitField.Flags.ManageMessages)) {
      await message.delete().catch(() => {});
      await log(message.guild, "Posible phishing", `Mensaje sospechoso de <@${message.author.id}> en <#${message.channel.id}>.`, 0xE74C3C);
      return;
    }
  }

  // Anti-mentions
  if (config.security.antiMentions && message.mentions.users.size >= 5) {
    await message.delete().catch(() => {});
    await log(message.guild, "Menciones masivas", `<@${message.author.id}> envió demasiadas menciones.`, 0xE74C3C);
    return;
  }

  // Anti-spam / Anti-flood
  if (config.security.antiSpam || config.security.antiFlood) {
    const history = recentMessages.get(key) || [];
    history.push({ content: message.content, time: nowTime });

    const recent = history.filter(x => nowTime - x.time < 7000);
    recentMessages.set(key, recent);

    const repeated = recent.filter(x => x.content === message.content).length >= 4;
    const flooding = recent.length >= 7;

    if ((config.security.antiSpam && repeated) ||
        (config.security.antiFlood && flooding)) {
      await message.delete().catch(() => {});

      if (member.moderatable) {
        await member.timeout(60 * 1000, "Protección automática anti-spam").catch(() => {});
      }

      await log(message.guild, "Anti-Spam", `<@${message.author.id}> activó una protección automática.`, 0xE74C3C);
    }
  }

  // Deleted message logging
  message.guild.channels.cache;
});

client.on("messageDelete", async message => {
  if (!message.guild || message.author?.bot) return;
  const content = message.content || "Contenido no disponible";
  await log(message.guild, "Mensaje eliminado",
    `Autor: ${message.author ? `<@${message.author.id}>` : "Desconocido"}\nCanal: <#${message.channel.id}>\nContenido: ${content.slice(0, 1500)}`);
});

client.on("messageUpdate", async (oldMessage, newMessage) => {
  if (!newMessage.guild || newMessage.author?.bot) return;
  if (oldMessage.content === newMessage.content) return;

  await log(newMessage.guild, "Mensaje editado",
    `Autor: <@${newMessage.author.id}>\nCanal: <#${newMessage.channel.id}>\nAntes: ${(oldMessage.content || "No disponible").slice(0, 700)}\nDespués: ${(newMessage.content || "No disponible").slice(0, 700)}`);
});

// Anti-raid and anti-bot
client.on("guildMemberAdd", async member => {
  const config = getServer(member.guild.id);

  if (config.welcome) {
    const channel = member.guild.channels.cache.get(config.welcome);
    if (channel?.isTextBased()) {
      channel.send({
        embeds: [embed("¡Bienvenido!", `¡Bienvenido/a ${member} a **${member.guild.name}**!`)]
      }).catch(() => {});
    }
  }

  if (config.autorole) {
    const role = member.guild.roles.cache.get(config.autorole);
    if (role && role.position < member.guild.members.me.roles.highest.position) {
      await member.roles.add(role).catch(() => {});
    }
  }

  if (member.user.bot && config.security.antiBot && !isWhitelisted(member.guild.id, member.id)) {
    await member.kick("Bot no autorizado: protección Sentinel").catch(() => {});
    await log(member.guild, "Anti-Bot", `Se rechazó el bot ${member.user.tag}.`, 0xE74C3C);
    return;
  }

  if (config.security.antiRaid) {
    const history = joinHistory.get(member.guild.id) || [];
    history.push(Date.now());

    const recent = history.filter(t => Date.now() - t < 10000);
    joinHistory.set(member.guild.id, recent);

    if (recent.length >= 8) {
      await log(member.guild, "Posible raid", `${recent.length} usuarios entraron en 10 segundos. Revisá el servidor.`, 0xE74C3C);
    }
  }

  await log(member.guild, "Usuario entró", `${member.user.tag} (${member.id})`);
});

client.on("guildMemberRemove", async member => {
  const config = getServer(member.guild.id);

  if (config.goodbye) {
    const channel = member.guild.channels.cache.get(config.goodbye);
    if (channel?.isTextBased()) {
      channel.send({
        embeds: [embed("Hasta pronto", `**${member.user.tag}** salió del servidor.`)]
      }).catch(() => {});
    }
  }

  await log(member.guild, "Usuario salió", `${member.user.tag} (${member.id})`);
});

// Anti-webhook: alerta sobre creación de webhooks
client.on("webhookUpdate", async channel => {
  const config = getServer(channel.guild.id);
  if (!config.security.antiWebhook) return;

  await log(channel.guild, "Cambio de webhook",
    `Se detectó una modificación de webhooks en <#${channel.id}>. Revisá los registros de auditoría.`,
    0xE74C3C);
});

// Anti-nuke: alertar ante creación o eliminación masiva de canales/roles
const destructiveEvents = [
  AuditLogEvent.ChannelDelete,
  AuditLogEvent.RoleDelete,
  AuditLogEvent.WebhookCreate,
  AuditLogEvent.BotAdd
];

client.on("guildAuditLogEntryCreate", async (entry, guild) => {
  const config = getServer(guild.id);
  if (!config.security.antiNuke) return;
  if (!destructiveEvents.includes(entry.action)) return;

  const executorId = entry.executorId;
  if (!executorId || isWhitelisted(guild.id, executorId)) return;

  await log(guild, "Alerta Anti-Nuke",
    `Acción detectada: **${entry.action}**\nResponsable: <@${executorId}>\nRevisá los registros de auditoría inmediatamente.`,
    0xE74C3C);
});

// =====================================
// TICKETS
// =====================================

client.on("interactionCreate", async interaction => {
  try {
    if (interaction.isChatInputCommand()) {
      await slashCommand(interaction);
      return;
    }

    if (!interaction.isButton()) return;

    if (interaction.customId === "sentinel_ticket_create") {
      const config = getServer(interaction.guild.id);

      if (!config.ticketCategory) {
        return reply(interaction, "Todavía no se configuró la categoría de tickets.", 0xE74C3C);
      }

      const existing = interaction.guild.channels.cache.find(channel =>
        channel.name === `ticket-${interaction.user.id}`
      );

      if (existing) return reply(interaction, `Ya tenés un ticket abierto: ${existing}`);

      const channel = await interaction.guild.channels.create({
        name: `ticket-${interaction.user.id}`,
        type: ChannelType.GuildText,
        parent: config.ticketCategory,
        permissionOverwrites: [
          {
            id: interaction.guild.roles.everyone.id,
            deny: [PermissionsBitField.Flags.ViewChannel]
          },
          {
            id: interaction.user.id,
            allow: [
              PermissionsBitField.Flags.ViewChannel,
              PermissionsBitField.Flags.SendMessages,
              PermissionsBitField.Flags.ReadMessageHistory
            ]
          },
          {
            id: client.user.id,
            allow: [
              PermissionsBitField.Flags.ViewChannel,
              PermissionsBitField.Flags.SendMessages,
              PermissionsBitField.Flags.ManageChannels
            ]
          }
        ]
      });

      if (config.ticketSupportRole) {
        await channel.permissionOverwrites.edit(config.ticketSupportRole, {
          ViewChannel: true,
          SendMessages: true,
          ReadMessageHistory: true
        }).catch(() => {});
      }

      await channel.send({
        content: `${interaction.user}`,
        embeds: [embed("Ticket abierto", "Contanos qué necesitás. El equipo de soporte te atenderá pronto.")],
        components: [
          new ActionRowBuilder().addComponents(
            new ButtonBuilder()
              .setCustomId("sentinel_ticket_close")
              .setLabel("Cerrar ticket")
              .setStyle(ButtonStyle.Danger)
              .setEmoji("🔒")
          )
        ]
      });

      return reply(interaction, `Ticket creado: ${channel}`);
    }

    if (interaction.customId === "sentinel_ticket_close") {
      if (!interaction.channel.name.startsWith("ticket-")) {
        return reply(interaction, "Este canal no es un ticket.");
      }

      const ownerId = interaction.channel.name.replace("ticket-", "");
      const canClose = interaction.user.id === ownerId ||
        interaction.memberPermissions?.has(PermissionsBitField.Flags.ManageChannels);

      if (!canClose) return reply(interaction, "No podés cerrar este ticket.", 0xE74C3C);

      await reply(interaction, "Ticket cerrado. Este canal se eliminará.");
      setTimeout(() => {
        interaction.channel.delete("Ticket cerrado").catch(() => {});
      }, 3000);
    }
  } catch (error) {
    console.error("Error en interacción:", error);

    if (interaction.isRepliable() && !interaction.replied && !interaction.deferred) {
      await interaction.reply({
        content: "Ocurrió un error al procesar la acción.",
        ephemeral: true
      }).catch(() => {});
    }
  }
});

// =====================================
// READY / REGISTRO SLASH
// =====================================

client.once("ready", async () => {
  console.log(`Sentinel conectado como ${client.user.tag}`);

  client.user.setActivity(
    `Observando ${client.guilds.cache.size} servidores`,
    { type: ActivityType.Watching }
  );

  const rest = new REST({ version: "10" }).setToken(TOKEN);

  try {
    await rest.put(
      Routes.applicationCommands(CLIENT_ID),
      { body: commands.map(command => command.toJSON()) }
    );

    console.log("Comandos slash registrados.");
  } catch (error) {
    console.error("Error registrando comandos:", error);
  }
});

client.on("guildCreate", () => {
  client.user.setActivity(
    `Observando ${client.guilds.cache.size} servidores`,
    { type: ActivityType.Watching }
  );
});

client.on("guildDelete", () => {
  client.user.setActivity(
    `Observando ${client.guilds.cache.size} servidores`,
    { type: ActivityType.Watching }
  );
});

client.login(TOKEN);
