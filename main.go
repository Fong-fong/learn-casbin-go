package main

import (
	"github.com/casbin/casbin/v2"
	"github.com/gofiber/fiber/v2"
	"log"
)

type requestEnforce struct {
	Subject string `json:"subject"`
	Domain  string `json:"domain"`
	Object  string `json:"object"`
	Action  string `json:"action"`
}

type requestRole struct {
	Subject string `json:"subject"`
	Role    string `json:"role"`
}

func main() {
	app := fiber.New()

	enforcer, err := casbin.NewEnforcer("rbac_model.conf", "policy.csv")
	if err != nil {
		log.Fatal(err.Error())
	}

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	app.Get("/health", func(c *fiber.Ctx) error {
		var test struct {
			Status string `json:"status"`
		}
		if err := c.BodyParser(&test); err != nil {
			return c.Status(400).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		return c.Status(200).JSON(fiber.Map{
			"message": test,
		})
	})

	app.Post("/enforce", func(c *fiber.Ctx) error {
		req := new(requestEnforce)
		if err := c.BodyParser(req); err != nil {
			return c.Status(400).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		if err := enforcer.LoadPolicy(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		ok, reason, err := enforcer.EnforceEx(req.Subject, req.Domain, req.Object, req.Action)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		if !ok {
			return c.Status(403).JSON(fiber.Map{
				"message": "forbidden",
			})
		}
		return c.Status(200).JSON(fiber.Map{
			"message": reason,
		})

	})

	app.Get("/domain", func(c *fiber.Ctx) error {
		if err := enforcer.LoadPolicy(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		domains, err := enforcer.GetAllDomains()
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		return c.JSON(
			fiber.Map{
				"domains": domains,
			})
	})

	app.Get("/roles", func(c *fiber.Ctx) error {
		if err := enforcer.LoadPolicy(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		roles, err := enforcer.GetAllRoles()
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		return c.JSON(
			fiber.Map{
				"roles": roles,
			})
	})

	member := app.Group("/members/:domain")

	member.Get("/", func(c *fiber.Ctx) error {
		domain := c.Params("domain")
		if err := enforcer.LoadPolicy(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		members, err := enforcer.GetFilteredGroupingPolicy(2, domain)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		return c.JSON(
			fiber.Map{
				"members": members,
			})
	})

	member.Post("/", func(c *fiber.Ctx) error {
		domain := c.Params("domain")
		req := new(requestRole)
		if err := c.BodyParser(req); err != nil {
			return c.Status(400).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		if req.Role != "owner" && req.Role != "moderator" {
			return c.Status(400).JSON(fiber.Map{
				"error": "role must be owner or moderator",
			})
		}

		if err := enforcer.LoadPolicy(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		ok, err := enforcer.AddRoleForUserInDomain(req.Subject, req.Role, domain)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		if err := enforcer.SavePolicy(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		if !ok {
			return c.Status(400).JSON(fiber.Map{
				"error": "failed to add role",
			})
		}
		return c.Status(200).JSON(fiber.Map{
			"message": "role added",
		})
	})

	member.Put("/", func(c *fiber.Ctx) error {
		domain := c.Params("domain")
		req := new(requestRole)
		if err := c.BodyParser(req); err != nil {
			return c.Status(400).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		if req.Role != "owner" && req.Role != "moderator" {
			return c.Status(400).JSON(fiber.Map{
				"error": "role must be owner or moderator",
			})
		}

		if err := enforcer.LoadPolicy(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		roles := enforcer.GetRolesForUserInDomain(req.Subject, domain)
		if len(roles) == 0 {
			return c.Status(400).JSON(fiber.Map{
				"error": "user does not exist",
			})
		}
		var oldPolicy = make([][]string, 0)
		for _, role := range roles {
			oldPolicy = append(oldPolicy, []string{req.Subject, role, domain})
		}
		var newPolicy = make([][]string, 0)
		newPolicy = append(newPolicy, []string{req.Subject, req.Role, domain})
		ok, err := enforcer.UpdateGroupingPolicies(oldPolicy, newPolicy)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		if err := enforcer.SavePolicy(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		if !ok {
			return c.Status(400).JSON(fiber.Map{
				"error": "failed to delete role",
			})
		}
		return c.Status(200).JSON(fiber.Map{
			"message": "role updated",
		})
	})

	member.Delete("/", func(c *fiber.Ctx) error {
		domain := c.Params("domain")
		var req struct {
			Subject string `json:"subject"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		if err := enforcer.LoadPolicy(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		roles := enforcer.GetRolesForUserInDomain(req.Subject, domain)
		if len(roles) == 0 {
			return c.Status(400).JSON(fiber.Map{
				"error": "user does not exist",
			})
		}
		var oldPolicy = make([][]string, 0)
		for _, role := range roles {
			oldPolicy = append(oldPolicy, []string{req.Subject, role, domain})
		}
		ok, err := enforcer.RemoveGroupingPolicies(oldPolicy)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		if err := enforcer.SavePolicy(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		if !ok {
			return c.Status(400).JSON(fiber.Map{
				"error": "failed to delete role",
			})
		}
		return c.Status(200).JSON(fiber.Map{
			"message": "role deleted",
		})
	})

	app.Get("/policies", func(c *fiber.Ctx) error {
		if err := enforcer.LoadPolicy(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		policies, err := enforcer.GetPolicy()
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		return c.JSON(
			fiber.Map{
				"policies": policies,
			})
	})

	app.Get("/groups", func(c *fiber.Ctx) error {
		if err := enforcer.LoadPolicy(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		groups, err := enforcer.GetGroupingPolicy()
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		return c.JSON(
			fiber.Map{
				"groups": groups,
			})
	})

	if err := app.Listen(":8088"); err != nil {
		panic(err)
	}
}
