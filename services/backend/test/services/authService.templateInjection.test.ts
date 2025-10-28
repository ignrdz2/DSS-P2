/**
2. Pruebas unitarias que validen la mitigación del Template Injection
identificado en la funcionalidad de envío de correo al crear un nuevo
usuario. Implementadas mediante JEST.
 
Funcionamiento:
- Inyecta payloads maliciosos en first_name/last_name y verifica que:
  1) El HTML del correo contiene los valores sanitisados (escapados).
  2) No aparecen los valores crudos sin escapar.
  3) El link de activación es correcto (contiene token y username).
  4) Se usa el transporte SMTP configurado por variables de entorno.
- En la rama con mitigaciones (p4tests) deben PASAR.
- En la rama con vulnerabilidades sin mitigar (maincopy) deberían FALLAR
  al detectar valores sin escape en el HTML del correo.
 
Diseño de la prueba
- Mocks: nodemailer (captura mailArg.html), db/knex (evita BD real), bcrypt (evita coste),
  crypto.randomBytes (token determinístico para validar el link).
- Entorno: define SMTP_HOST/PORT/USER/PASS y FRONTEND_URL.
- Aserciones: escaping, ausencia de crudo, link correcto, transporte SMTP correcto.
 
Cómo ejecutar:
Desde la extensión "JEST" o ejecutando el siguiente comando (desde services/backend)
npm test -- test/services/authService.templateInjection.test.ts
 */

import crypto from "crypto";

// Mock de nodemailer para capturar el HTML enviado
const mockSendMail = jest.fn().mockResolvedValue({});
const mockCreateTransport = jest.fn(() => ({ sendMail: mockSendMail }));
jest.mock("nodemailer", () => ({
  __esModule: true,
  default: { createTransport: mockCreateTransport },
}));

// Mock de la DB (tipo knex): where/orWhere/first/insert
const qb: any = {
  where: jest.fn(() => qb),
  orWhere: jest.fn(() => qb),
  first: jest.fn(async () => undefined), // usuario NO existe
  insert: jest.fn(async () => undefined),
};
const dbMock = jest.fn((_table: string) => qb);
jest.mock("../../src/db", () => ({
  __esModule: true,
  default: dbMock,
}));

// Mock de bcrypt.hash
jest.mock("bcrypt", () => ({
  __esModule: true,
  default: {
    hash: jest.fn(async () => "hashed-password"),
    compare: jest.fn(),
  },
}));

import AuthService from "../../src/services/authService";

describe("AuthService.createUser - mitigación Template Injection", () => {
  const ENV_BACKUP = process.env;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env = { ...ENV_BACKUP };
    process.env.SMTP_HOST = "localhost";
    process.env.SMTP_PORT = "1025";
    process.env.SMTP_USER = "user";
    process.env.SMTP_PASS = "pass";
    process.env.FRONTEND_URL = "http://localhost:3000";
  });

  afterAll(() => {
    process.env = ENV_BACKUP;
  });

  it("escapa correctamente campos maliciosos en el HTML del correo", async () => {
    const tokenHex = "abcdef123456"; // 6 bytes -> 12 hex
    const randomSpy = jest
      .spyOn(crypto as any, "randomBytes")
      .mockImplementation((size: number) => Buffer.from(tokenHex, "hex"));

    const user = {
      username: "alice",
      password: "P@ssw0rd!",
      email: "alice@example.com",
      first_name: "<%= 7*7 %>",
      last_name: "<script>alert(1)</script>",
    } as any;

    await AuthService.createUser(user);

    expect(mockCreateTransport).toHaveBeenCalledTimes(1);

    // Verificar config del transporte con las variables de entorno
    expect(mockCreateTransport).toHaveBeenCalledWith({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT as string),
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    expect(mockSendMail).toHaveBeenCalledTimes(1);

    const mailArg = mockSendMail.mock.calls[0][0];
    expect(mailArg.to).toBe(user.email);
    expect(String(mailArg.subject)).toMatch(/Activate your account/i);

    const html: string = mailArg.html;

    // Debe contener los nombres ESCAPADOS
    expect(html).toContain("&lt;%= 7*7 %&gt;");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");

    // No debe contener los nombres crudos
    expect(html).not.toContain("<%= 7*7 %>");
    expect(html).not.toContain("<script>alert(1)</script>");

    // Link correcto con token determinístico
    const expectedLink = `${process.env.FRONTEND_URL}/activate-user?token=${tokenHex}&username=${user.username}`;
    expect(html).toContain(expectedLink);

    // Limpiar el spy de crypto.randomBytes para no afectar otros tests
    randomSpy.mockRestore();
  });
});
