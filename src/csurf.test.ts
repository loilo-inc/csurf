import { describe, it, beforeAll, expect } from "vitest";
import cookieParser from "cookie-parser";
import express from "express";
import request from "supertest";
import type { CsrfOptions } from "./csurf";
import { csurf } from "./csurf";
import session from "cookie-session";

function cookie(res: Express.Response, name: string) {
  // @ts-ignore
  return res.headers["set-cookie"].filter(function (cookies: string) {
    return cookies.split("=")[0] === name;
  })[0];
}

function cookies(res: Express.Response) {
  return (
    // @ts-ignore
    res.headers["set-cookie"]
      .map(function (cookies: string) {
        return cookies.split(";")[0];
      })
      .join(";")
  );
}

function createTestServer(options?: CsrfOptions) {
  const app = express();

  if (!options || (options && !options.cookie)) {
    app.use(session({ keys: ["a", "b"] }));
  } else if (options && options.cookie) {
    app.use(cookieParser("keyboard cat"));
  }
  app.use(express.urlencoded({ extended: false }));
  app.use(csurf(options));
  app.get("/", function (req, res) {
    res.status(200).send(req.csrfToken());
  });
  app.post("/", function (req, res) {
    res.status(200).send({});
  });

  return app;
}

function plainTestServer() {
  const app = express();
  app.use(express.urlencoded({ extended: false }));
  return app;
}

describe("csurf", function () {
  it("should work in req.body", async () => {
    const app = createTestServer();
    // getのため403は返らず、tokenが返されてそのtokenを使ってpostする
    const res = await request(app).get("/").expect(200);
    var token = res.text;
    await request(app)
      .post("/")
      .set("Cookie", cookies(res))
      .send("_csrf=" + encodeURIComponent(token))
      .expect(200);
  });

  it("should work in req.query", async function () {
    const app = createTestServer();
    const res = await request(app).get("/").expect(200);
    const token = res.text;
    await request(app)
      .post("/?_csrf=" + encodeURIComponent(token))
      .set("Cookie", cookies(res))
      .expect((res) => {
        expect(res.text).toBe("{}");
      });
  });

  it("should work in csrf-token header", async function () {
    const app = createTestServer();
    const res = await request(app).get("/").expect(200);
    const token = res.text;
    await request(app)
      .post("/")
      .set("Cookie", cookies(res))
      .set("csrf-token", token)
      .expect(200);
  });

  it("should work in xsrf-token header", async function () {
    const app = createTestServer();
    const res = await request(app).get("/").expect(200);
    const token = res.text;
    await request(app)
      .post("/")
      .set("Cookie", cookies(res))
      .set("xsrf-token", token)
      .expect(200);
  });

  it("should work in x-csrf-token header", async () => {
    const app = createTestServer();
    const res = await request(app).get("/").expect(200);
    const token = res.text;
    await request(app)
      .post("/")
      .set("Cookie", cookies(res))
      .set("x-csrf-token", token)
      .expect(200);
  });

  it("should work in x-xsrf-token header", async function () {
    const app = createTestServer();
    const res = await request(app).get("/").expect(200);
    const token = res.text;
    await request(app)
      .post("/")
      .set("Cookie", cookies(res))
      .set("x-xsrf-token", token)
      .expect(200);
  });

  it("should fail with an invalid token", async function () {
    const app = createTestServer();
    const res = await request(app).get("/").expect(200);
    await request(app)
      .post("/")
      .set("Cookie", cookies(res))
      .set("X-CSRF-Token", "42")
      .expect(403);
  });

  it("should fail with no token", async function () {
    const app = createTestServer();
    const res = await request(app).get("/").expect(200);
    await request(app).post("/").set("Cookie", cookies(res)).expect(403);
  });

  it("should provide error code on invalid token error", async function () {
    const app = plainTestServer();

    app.use(session({ keys: ["a", "b"] }));
    app.use(csurf());

    app.use(function (
      req: express.Request,
      res: express.Response,
      next: express.NextFunction,
    ) {
      res.end(req.csrfToken() || "none");
    });

    app.use(function (
      err: Error,
      req: express.Request,
      res: express.Response,
      next: express.NextFunction,
    ) {
      // @ts-ignore
      if (err.code !== "EBADCSRFTOKEN") return next(err);
      res.statusCode = 403;
      res.end("session has expired or form tampered with");
    });

    const res = await request(app).get("/").expect(200);
    await request(app)
      .post("/")
      .set("Cookie", cookies(res))
      .set("X-CSRF-Token", String(res.text + "p"))
      .expect(403, "session has expired or form tampered with");
  });

  it("should error without session secret storage", async function () {
    const app = plainTestServer();
    app.use(csurf());
    await request(app)
      .get("/")
      .expect(500, /misconfigured csrf/);
  });

  describe('with "cookie" option', function () {
    describe("when true", function () {
      it('should store secret in "_csrf" cookie', async function () {
        var server = createTestServer({ cookie: true });

        const res = await request(server).get("/").expect(200);
        var data = cookie(res, "_csrf");
        var token = res.text;

        expect(data).toBeTruthy();
        expect(/; *path=\/(?:;|$)/i.test(data)).toBeTruthy();

        await request(server)
          .post("/")
          .set("Cookie", cookies(res))
          .set("X-CSRF-Token", token)
          .expect(200);
      });

      it("should append cookie to existing Set-Cookie header", async function () {
        const app = plainTestServer();
        app.use(cookieParser("keyboard cat"));
        app.use(function (
          req: express.Request,
          res: express.Response,
          next: express.NextFunction,
        ) {
          res.setHeader("Set-Cookie", "foo=bar");
          next();
        });
        app.use(csurf({ cookie: true }));
        app.get("/", function (req, res) {
          res.status(200).send(req.csrfToken());
        });
        app.post("/", function (req, res) {
          res.status(200).send({});
        });

        const res = await request(app).get("/").expect(200);

        var token = res.text;

        expect(cookie(res, "_csrf")).toBeTruthy();
        expect(cookie(res, "foo")).toBeTruthy();

        request(app)
          .post("/")
          .set("Cookie", cookies(res))
          .set("X-CSRF-Token", token)
          .expect(200);
      });
    });

    describe("when an object", function () {
      it('should configure the cookie name with "key"', async function () {
        var server = createTestServer({ cookie: { key: "_customcsrf" } });

        const res = await request(server).get("/").expect(200);
        var data = cookie(res, "_customcsrf");
        var token = res.text;

        expect(data).toBeTruthy();
        expect(/; *path=\/(?:;|$)/i.test(data)).toBeTruthy();

        await request(server)
          .post("/")
          .set("Cookie", cookies(res))
          .set("X-CSRF-Token", token)
          .expect(200);
      });

      it('should keep default cookie name when "key: undefined"', async function () {
        var server = createTestServer({ cookie: { key: undefined } });

        const res = await request(server).get("/").expect(200);
        var data = cookie(res, "_csrf");
        var token = res.text;

        expect(data).toBeTruthy();
        expect(/; *path=\/(?:;|$)/i.test(data)).toBeTruthy();

        await request(server)
          .post("/")
          .set("Cookie", cookies(res))
          .set("X-CSRF-Token", token)
          .expect(200);
      });

      describe('when "signed": true', function () {
        it("should enable signing", async function () {
          var server = createTestServer({ cookie: { signed: true } });

          const res = await request(server).get("/").expect(200);
          var data = cookie(res, "_csrf");
          var token = res.text;

          expect(data).toBeTruthy();
          expect(/^_csrf=s%3A/i.test(data)).toBeTruthy();

          await request(server)
            .post("/")
            .set("Cookie", cookies(res))
            .set("X-CSRF-Token", token)
            .expect(200);
        });

        it("should error without cookieParser", async function () {
          const app = plainTestServer();

          app.use(csurf({ cookie: { signed: true } }));

          await request(app)
            .get("/")
            .expect(500, /misconfigured csrf/);
        });

        it("should error when cookieParser is missing secret", async function () {
          const app = plainTestServer();

          app.use(cookieParser());
          app.use(csurf({ cookie: { signed: true } }));

          await request(app)
            .get("/")
            .expect(500, /misconfigured csrf/);
        });
      });
    });
  });

  describe('with "ignoreMethods" option', function () {
    it("should not check token on given methods", async function () {
      var server = createTestServer({ ignoreMethods: ["GET", "POST"] });
      server.put("/", function (req, res) {
        res.status(200).send({});
      });

      const res = await request(server).get("/").expect(200);
      var cookie = cookies(res);
      await request(server).post("/").set("Cookie", cookie).expect(200);
      await request(server).put("/").set("Cookie", cookie).expect(403);
    });
  });

  describe('with "sessionKey" option', function () {
    it("should use the specified sessionKey", async function () {
      const app = plainTestServer();
      const sess = {};

      app.use(function (
        req: express.Request,
        res: express.Response,
        next: express.NextFunction,
      ) {
        // @ts-ignore
        req.mySession = sess;
        next();
      });
      app.use(express.urlencoded({ extended: false }));
      app.use(csurf({ sessionKey: "mySession" }));
      app.use(function (
        req: express.Request,
        res: express.Response,
        next: express.NextFunction,
      ) {
        res.end(req.csrfToken() || "none");
      });

      const res = await request(app).get("/").expect(200);
      var token = res.text;

      await request(app)
        .post("/")
        .send("_csrf=" + encodeURIComponent(token))
        .expect(200);
    });
  });

  describe("req.csrfToken()", function () {
    it("should return same token for each call", async function () {
      const app = plainTestServer();
      app.use(session({ keys: ["a", "b"] }));
      app.use(csurf({}));
      app.use(function (req: express.Request, res: express.Response) {
        var token1 = req.csrfToken();
        var token2 = req.csrfToken();
        res.end(String(token1 === token2));
      });

      await request(app).get("/").expect(200, "true");
    });

    it("should error when secret storage missing", async function () {
      const app = plainTestServer();

      app.use(session({ keys: ["a", "b"] }));
      app.use(csurf({}));
      app.use(function (req: express.Request, res: express.Response) {
        //@ts-ignore
        req.session = undefined;
        res.setHeader("x-run", "true");
        res.end(req.csrfToken());
      });

      await request(app)
        .get("/")
        .expect("x-run", "true")
        .expect(500, /misconfigured csrf/);
    });
  });

  describe("when using session storage", function () {
    let app: express.Express;
    beforeAll(function () {
      app = express();
      app.use(session({ keys: ["a", "b"] }));
      app.use(csurf());
      app.use("/break", function (req, res, next) {
        // break session
        // @ts-ignore
        req.session = null;
        next();
      });
      app.use("/new", function (req, res, next) {
        // regenerate session
        // @ts-ignore
        req.session = { hit: 1 };
        next();
      });
      app.use(function (req, res) {
        res.end(req.csrfToken() || "none");
      });
    });

    it("should work with a valid token", async function () {
      const res = await request(app).get("/").expect(200);
      var token = res.text;
      await request(app)
        .post("/")
        .set("Cookie", cookies(res))
        .set("X-CSRF-Token", token)
        .expect(200);
    });

    it("should provide a valid token when session regenerated", async function () {
      const res = await request(app).get("/new").expect(200);
      var token = res.text;
      await request(app)
        .post("/")
        .set("Cookie", cookies(res))
        .set("X-CSRF-Token", token)
        .expect(200);
    });

    it("should error if session missing", async function () {
      await request(app)
        .get("/break")
        .expect(500, /misconfigured csrf/);
    });
  });
});
