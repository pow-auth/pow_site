---
layout:  guide
title:   "Custom password validation validation"
date:    2019-09-14 15:38:05 -0100
author:  Maarten van Vliet
---

A common requirement for password validation is to check whether the password
has been used elsewhere on a breached site. The most popular service for this is
[haveibeenpwned.com](https://haveibeenpwned.com/). This guide will illustrate
how to add validation such as `haveibeenpwned.com` but also add other validation rules for your passwords to Pow.


### Add haveibeenpwned.com validation

First we need to install an api client for `haveibeenpwned.com`. In this guide 
[`ExPwned`](https://hex.pm/packages/ex_pwned) is used but any other client will follow the same principle.

Add `ExPwned` to your `mix.exs` file and run `mix deps.get` afterwards. 

```elixir
# mix.exs
def deps do
  [
    ...
    {:ex_pwned, "~> 0.1.0"}
    ...
  ]
end
```

ExPwned has a simple api. You can check whether a password is breached with the 
following command.

```elixir
iex> ExPwned.breached?("abc@example.com")
true
```

To add this to validation to Pow, the user changeset needs to be adapted.

```elixir
defmodule PowTest.Users.User do
  use Ecto.Schema
  use Pow.Ecto.Schema

  ...

  def changeset(user_or_changeset, attrs) do
    user_or_changeset
    |> pow_changeset(attrs)
    |> Ecto.Changeset.validate_change(:password, fn :password, password ->
      case ExPwned.password_breached?(password) do
        false ->
          []

        true ->
          [password: "This password has appeared in a data breach."]
      end
    end)
  end
end
```

In the [Ecto.Changeset.validate_change/3](https://hexdocs.pm/ecto/Ecto.Changeset.html#validate_change/3) function, `ExPwned` validates whether the password was used in a breach. If not, an empty list is returned, meaning that no errors are added to the changeset. If the password has been used, an error is added to the password field.

### Adding custom password rules

By default Pow checks that the password has at least 10 characters. You might want to add extra rules like disallowing repetitive characters.

This can be done by using the [Ecto.Changeset.validate_format/4](https://hexdocs.pm/ecto/Ecto.Changeset.html#validate_format/4) validator.

```elixir
  def changeset(user_or_changeset, attrs) do
    user_or_changeset
    |> pow_changeset(attrs)
    |> Ecto.Changeset.validate_format(:password, ~r/(.)\1{2,}/,
      message: "This password has the same character repeated"
    )
  end
```
See [this list](https://github.com/langleyfoxall/laravel-nist-password-rules) for extra validators that could be added.

You can see it is easy to extend the password validation rules of Pow and add your own.

