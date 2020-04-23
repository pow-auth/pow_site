---
layout: guide
title:  "Resend email confirmation link"
date:   2020-03-07 14:23:00 -0700
author: Dan Schultzer
---

You may wish to add a link to the account edit page so users can manually request the confirmation e-mail to be send again in case they didn't receive it the first time.

First add a controller with an action to resend the confirmation e-mail. Create `WEB_PATH/controllers/registration_controller.ex`:

```elixir
defmodule MyAppWeb.RegistrationController do
  use MyAppWeb, :controller

  def resend_confirmation_email(conn, _params) do
    case PowEmailConfirmation.Plug.pending_email_change?(conn) do
      true ->
        send_confirmation_email(conn)

        conn
        |> put_flash(:info, "E-mail sent, please check your inbox.")
        |> redirect(to: Routes.pow_registration_path(conn, :edit))

      false ->
        conn
        |> put_flash(:info, "E-mail has already been confirmed.")
        |> redirect(to: Routes.pow_registration_path(conn, :edit))
    end
  end

  defp send_confirmation_email(conn) do
    user = Pow.Plug.current_user(conn)

    PowEmailConfirmation.Phoenix.ControllerCallbacks.send_confirmation_email(user, conn)
  end
end
```

Update `WEB_PATH/router.ex` with the route (and it should only accessible for authenticated users):

```elixir
defmodule MyAppWeb.Router do
  use MyAppWeb, :router
  use Pow.Phoenix.Router

  # ... pipelines

  pipeline :protected do
    plug Pow.Plug.RequireAuthenticated,
      error_handler: Pow.Phoenix.PlugErrorHandler
  end

  scope "/", MyAppWeb do
    pipe_through [:browser, :protected]

    post "/registration/send-confirmation-email", RegistrationController, :resend_confirmation_email
  end

  # ...
end
```

Add the following section to your `WEB_PATH/templates/pow/registration/edit.html.eex` template (you may need to generate the templates first) after the `pow_user_id_field` field:

```elixir
<%= if @changeset.data.unconfirmed_email do %>
  <div>
    <p>Click the link in the confirmation email to change your email to <%= content_tag(:span, @changeset.data.unconfirmed_email) %>. Still haven't received the email? <%= link("Click here to send again", to: Routes.registration_path(@conn, :resend_confirmation_email), method: :post) %>.</p>
  </div>
<% end %>
```

That's it!

## Security

As mentioned in the [production checklist](https://hexdocs.pm/pow/production_checklist.html#optional-rate-limit-e-mail-delivery), you should consider adding rate limitation to e-mail delivery. Otherwise the platform may be vulnerable to resource usage attacks.

## Controller test

```elixir
defmodule MyAppWeb.RegistrationControllerTest do
  use MyAppWeb.ConnCase

  alias MyApp.{Users.User, Repo}

  setup %{conn: conn} do
    {:ok, user} =
      Pow.Ecto.Context.create(%{
        email: "test@example.com",
        password: "secret1234",
        password_confirmation: "secret1234"
      }, repo: Repo, user: User)

    {:ok, user} =
      Pow.Ecto.Context.update(user, %{
        email: "updated@example.com",
        current_password: "secret1234"
      }, repo: Repo, user: User)

    conn = Pow.Plug.assign_current_user(conn, user, otp_app: :my_app)

    {:ok, conn: conn, user: user}
  end

  describe "resend_confirmation_email/2" do
    test "sends confirmation email", %{conn: conn} do
      conn = post conn, Routes.registration_path(conn, :resend_confirmation_email)

      assert redirected_to(conn) == Routes.pow_registration_path(conn, :edit)
      assert get_flash(conn, :info) == "E-mail sent, please check your inbox."
    end

    test "with already confirmed email", %{conn: conn, user: user} do
      user = PowEmailConfirmation.Ecto.Context.confirm_email(user, %{}, otp_app: :my_app)

      conn =
        conn
        |> Pow.Plug.assign_current_user(user, otp_app: :my_app)
        |> post(Routes.registration_path(conn, :resend_confirmation_email))

      assert redirected_to(conn) == Routes.pow_registration_path(conn, :edit)
      assert get_flash(conn, :info) == "E-mail has already been confirmed."
    end
  end
end
```
