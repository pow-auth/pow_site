---
layout: guide
title:  "Password breach lookup and other password validation rules"
date:   2019-09-14 15:38:05 -0100
author: Maarten van Vliet, Dan Schultzer
---

By default Pow has a lax requirement of minimum 8 characters based on [NIST SP800-63b](https://pages.nist.gov/800-63-3/sp800-63b.html), but there are many more types of validations you can use to ensure users don't rely on weak passwords.

An important aspect to password requirements is that it should be user friendly. Requirements to mix alphanumeric with symbols and upper- and lowercase characters haven't proven effective. In the following we'll go through some effective methods to ensure users uses strong passwords.

They are based on the [NIST SP800-63b recommendations](https://pages.nist.gov/800-63-3/sp800-63b.html):

- Passwords obtained from previous breaches
- Context-specific words, such as the name of the service, the username, and derivatives thereof
- Repetitive or sequential characters
- Dictionary words

## Passwords obtained from previous breaches

We'll use [haveibeenpwned.com](https://haveibeenpwned.com/) to check for breached passwords.

For the sake of brevity, we'll use [`ExPwned`](https://hex.pm/packages/ex_pwned) in the following example, but you can use any client or your own [custom module](https://ieftimov.com/post/haveibeenpwned-password-lookup-elixir/) to communicate with the API.

First, we'll add `ExPwned` to the `mix.exs` file:

```elixir
def deps do
  [
    ...
    {:ex_pwned, "~> 0.1.0"}
  ]
end
```

Run `mix deps.get` to install it.

Now let's add the password validation rule to our user schema module:

```elixir
defmodule MyApp.Users.User do
  use Ecto.Schema
  use Pow.Ecto.Schema

  # ...

  def changeset(user_or_changeset, attrs) do
    user_or_changeset
    |> pow_changeset(attrs)
    |> validate_password_breach()
  end

  defp validate_password_breach(changeset) do
    Ecto.Changeset.validate_change(changeset, :password, fn :password, password ->
      case password_breached?(password) do
        true  -> [password: "has appeared in a previous breach"]
        false -> []
      end
    end)
  end

  defp password_breached?(password) do
    case Mix.env() do
      :test -> false
      _any  -> ExPwned.password_breached?(password)
    end
  end
end
```

We'll only do a lookup if the password has been changed, and we don't do any lookups in test environment.

## Context-specific words, such as the name of the service, the username, and derivatives thereof

We want to prevent context specific words to be used as passwords.

The context might be public user details. If the users email is `john.doe@example.com` then the password can't be `john.doe@example.com` or `johndoeexamplecom`. The same rule applies for any user id we may use, such as username. If the username is `john.doe` then `john.doe00` or `johndoe001` can't be used.

Our app may also be part of a website/service/platform and have an identity. As an example, if the service is called `My Demo App` then we don't want to permit passwords like `my demo app`, `my_demo_app` or `mydemoapp`.

We'll add the password validation rule to our user schema module:

```elixir
defmodule MyApp.Users.User do
  use Ecto.Schema
  use Pow.Ecto.Schema

  # ...

  def changeset(user_or_changeset, attrs) do
    user_or_changeset
    |> pow_changeset(attrs)
    |> validate_password_no_context()
  end

  @app_name "My Demo App"

  defp validate_password_no_context(changeset) do
    Ecto.Changeset.validate_change(changeset, :password, fn :password, password ->
      [
        @app_name,
        String.downcase(@app_name),
        Ecto.Changeset.get_field(changeset, :email),
        Ecto.Changeset.get_field(changeset, :username)
      ]
      |> Enum.reject(&is_nil/1)
      |> similar_to_context?(password)
      |> case do
        true  -> [password: "is too similar to username, email or #{@app_name}"]
        false -> []
      end
    end)
  end

  def similar_to_context?(contexts, password) do
    Enum.any?(contexts, &String.jaro_distance(&1, password) > 0.85)
  end
end
```

We're using the [`String.jaro_distance/2`](https://hexdocs.pm/elixir/String.html#jaro_distance/2) to make sure that the password has a Jaro–Winkler similarity to the context of at most `0.85`.

## Repetitive or sequential characters

We want to prevent repetitive or sequential characters in passwords such as `aaa`, `1234` or `abcd`.

The rule we'll use is that there may be no more than two repeating or three sequential characters in the password. We'll add the validation rule to our user schema module:

```elixir
defmodule MyApp.Users.User do
  use Ecto.Schema
  use Pow.Ecto.Schema

  # ...

  def changeset(user_or_changeset, attrs) do
    user_or_changeset
    |> pow_changeset(attrs)
    |> validate_password()
  end

  defp validate_password(changeset) do
    changeset
    |> validate_no_repetitive_characters()
    |> validate_no_sequential_characters()
  end

  defp validate_no_repetitive_characters(changeset) do
    Ecto.Changeset.validate_change(changeset, :password, fn :password, password ->
      case repetitive_characters?(password) do
        true  -> [password: "has repetitive characters"]
        false -> []
      end
    end)
  end

  defp repetitive_characters?(password) when is_binary(password) do
    password
    |> String.to_charlist()
    |> repetitive_characters?()
  end
  defp repetitive_characters?([c, c, c | _rest]), do: true
  defp repetitive_characters?([_c | rest]), do: repetitive_characters?(rest)
  defp repetitive_characters?([]), do: false

  defp validate_no_sequential_characters(changeset) do
    Ecto.Changeset.validate_change(changeset, :password, fn :password, password ->
      case sequential_characters?(password) do
        true  -> [password: "has sequential characters"]
        false -> []
      end
    end)
  end

  @sequences ["01234567890", "abcdefghijklmnopqrstuvwxyz"]
  @max_sequential_chars 3

  defp sequential_characters?(password) do
    Enum.any?(@sequences, &sequential_characters?(password, &1))
  end

  defp sequential_characters?(password, sequence) do
    max = String.length(sequence) - 1 - @max_sequential_chars

    Enum.any?(0..max, fn x ->
      pattern = String.slice(sequence, x, @max_sequential_chars + 1)

      String.contains?(password, pattern)
    end)
  end
end
```

As you can see, you'll be able to modify `@sequences` and add what is appropriate for your app. It may be that you want to support another alphabet or keyboard layout sequences like `qwerty`.

## Dictionary words

A dictionary lookup is very easy to create. This is just a very simple example that you can add to your user schema module:

```elixir
defmodule MyApp.Users.User do
  use Ecto.Schema
  use Pow.Ecto.Schema

  # ...

  def changeset(user_or_changeset, attrs) do
    user_or_changeset
    |> pow_changeset(attrs)
    |> validate_password_dictionary()
  end

  defp validate_password_dictionary(changeset) do
    Ecto.Changeset.validate_change(changeset, :password, fn :password, password ->
      password
      |> String.downcase()
      |> password_in_dictionary?()
      |> case do
        true  -> [password: "is too common"]
        false -> []
      end
    end)
  end

  :my_app
  |> :code.priv_dir()
  |> Path.join("dictionary.txt")
  |> File.stream!()
  |> Stream.map(&String.trim/1)
  |> Stream.each(fn password ->
    defp password_in_dictionary?(unquote(password)), do: true
  end)
  |> Stream.run()

  defp password_in_dictionary?(_password), do: false
end
```

In the above `priv/dictionary.txt` will be processed on compile time. The plain text file contains words separated by newline.

## Require users to change weak password upon sign in

You may want to ensure that users update their password if they have been breached or are too weak. You can do this be requiring users to reset their password upon sign in.

This can be dealt with in a plug, or [custom controller](https://hexdocs.pm/pow/custom_controllers.html). A plug method could look like this:

```elixir
def check_password(conn, _opts) do
  changeset = MyApp.Users.User.changeset(%MyApp.Users.User{}, conn.params["user"])

  case changeset.errors[:password] do
    nil ->
      conn

    error ->
      msg = MyAppWeb.ErrorHelpers.translate_error(error)

      conn
      |> put_flash(:error, "You have to reset your password because it #{msg}")
      |> redirect(to: Routes.pow_reset_password_reset_password_path(conn, :new))
      |> Plug.Conn.halt()
  end
end
```

The user will be redirected to the reset password page, and the connection halted so authentication won't happen. A caveat to this is that the user may not have entered valid credentials, since this runs before any authentication.

## Conclusion

As you can see it is easy to customize and extend the password validation rules of Pow.

The landscape of web security is constantly changing, so it's important that password requirements are neither so restricting that it affects user experience or too lax that it affects security. The above will work for most cases in the current landscape, but you should also consider supporting 2FA authentication, or alternative authentication schemes such as WebAuthn or OAuth.

It depends on your requirements and risk tolerance. It's recommended to take your time to assess what is appropriate for your app.

## Unit tests

Here is a unit test module that contains tests for two of of the above rulesets:

```elixir
defmodule MyApp.Users.UserTest do
  use MyApp.DataCase

  alias MyApp.Users.User

  test "changeset/2 validates context-specific words" do
    for invalid <- ["my demo app", "mydemo_app", "mydemoapp1"] do
      changeset = User.changeset(%User{}, %{"username" => "john.doe", "password" => invalid})
      assert changeset.errors[:password] == {"is too similar to username, email or My Demo App", []}
    end

    # The below is for email user id
    changeset = User.changeset(%User{}, %{"email" => "john.doe@example.com", "password" => "password12"})
    refute changeset.errors[:password]

    for invalid <- ["john.doe@example.com", "johndoeexamplecom"] do
      changeset = User.changeset(%User{}, %{"email" => "john.doe@example.com", "password" => invalid})
      assert changeset.errors[:password] == {"is too similar to username, email or My Demo App", []}
    end

    # The below is for username user id
    changeset = User.changeset(%User{}, %{"username" => "john.doe", "password" => "password12"})
    refute changeset.errors[:password]

    for invalid <- ["john.doe00", "johndoe", "johndoe1"] do
      changeset = User.changeset(%User{}, %{"username" => "john.doe", "password" => invalid})
      assert changeset.errors[:password] == {"is too similar to username, email or My Demo App", []}
    end
  end

  test "changeset/2 validates repetitive and sequential password" do
    changeset = User.changeset(%User{}, %{"password" => "secret1222"})
    assert changeset.errors[:password] == {"has repetitive characters", []}

    changeset = User.changeset(%User{}, %{"password" => "secret1223"})
    refute changeset.errors[:password]

    changeset = User.changeset(%User{}, %{"password" => "secret1234"})
    assert changeset.errors[:password] == {"has sequential characters", []}

    changeset = User.changeset(%User{}, %{"password" => "secret1235"})
    refute changeset.errors[:password]

    changeset = User.changeset(%User{}, %{"password" => "secretefgh"})
    assert changeset.errors[:password] == {"has sequential characters", []}

    changeset = User.changeset(%User{}, %{"password" => "secretafgh"})
    refute changeset.errors[:password]
  end
end
```
