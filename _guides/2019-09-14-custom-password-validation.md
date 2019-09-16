---
layout:  guide
title:   "Password breach lookup and other password validation rules"
date:    2019-09-14 15:38:05 -0100
author:  Maarten van Vliet, Dan Schultzer
---

By default Pow has a lax requirement of minimum 10 characters based on OWASP recommendations, but there are many more types of validations you can use to ensure users don't rely on weak passwords.

An important aspect to password requirements is that it should be user friendly. Requirements to mix alphanumeric with symbols and upper- and lowercase characters haven't proven effective. In the following we'll go through some effective methods to ensure users uses strong passwords.

They are based on the [NIST SP800-63b recommendations](https://pages.nist.gov/800-63-3/sp800-63b.html):

- Passwords obtained from previous breaches
- Context-specific words, such as the name of the service, the username, and derivatives thereof
- Repetitive or sequential characters
- Dictionary words

## Passwords obtained from previous breaches

To check for breached passwords, we'll use the [haveibeenpwned.com](https://haveibeenpwned.com/).

For the sake of brevity, we'll use [`ExPwned`](https://hex.pm/packages/ex_pwned) in the following example, but you can use any client or your own custom module to communicate with the API.

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

Now let's add the password validation rule to the user module:

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
      cond do
        is_nil(changeset.errors[:email]) -> []
        password_breached?(password)     -> [password: "has appeared in a previous breach"]
        true                             -> []
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

API lookups are expensive so we'll only do a lookup if the password has been changed, and the field doesn't already have an error. We also don't do any lookups in test environment.

## Context-specific words, such as the name of the service, the username, and derivatives thereof

We want to prevent context specific words such as if the username is `john.doe`, the password can't be `john.doe`, `johndoe`, `johndoe1` and so on. Likewise, our platform may be called `My App`, so we don't want to permit a password that's very similar to the name like `myapp`, `my_app`, `my app` and so on.

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

  @app_name "My App"

  defp validate_password_no_context(changeset) do
    Ecto.Changeset.validate_change(changeset, :password, fn :password, password ->
      [
        @app_name,
        String.downcase(@app_name),
        Ecto.Changeset.get_field(changeset, :email),
        Ecto.Changeset.get_field(changeset, :username)
      ]
      |> similar_to_context?(password)
      |> case do
        true  -> [password: "is too similar to username, email or #{@app_name}"]
        false -> []
      end
    end)
  end

  def similar_to_context?(contexts, password) do
    Enum.any?(contexts, fn context ->
      String.jaro_distance(context, password) > 0.90
    end)
  end
end
```

We're using the [`String.jaro_distance/2`](https://hexdocs.pm/elixir/String.html#jaro_distance/2) to make sure that the password has a Jaro–Winkler similarity to the context of at most 0.9.

## Repetitive or sequential characters

We want to prevent repetitive passwords such as `aaa`, `1234` or `abcd`. We'll set up the following validations so there may be no more than two repeating or three sequential characters in the password.

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
        true  -> [password: "has repetitive characters"]
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

As you can see, you'll be able to modify `@sequences` and add what is appropriate for your app. It may be that you want to support another alphabet or keyboard sequences like `qwerty`.

## Dictionary words


## Require users to change weak password upon sign in


## Conclusion

As you can see it is easy to customize and extend the password validation rules of Pow.

The landscape of web security is constantly changing, so it's important that password requirements are neither so restricting that it affects user experience or too lax that it affects security. The above will work for most cases in the current landscape, but you should also consider supporting 2FA authentication, or alternative authentication schemes such as WebAuthn or OAuth. It depends on your requirements and risk tolerance. It's recommended to take your time to assess what is appropriate for your app.

## Unit tests

Here is a unit test module that contains tests for all of the above rulesets:
