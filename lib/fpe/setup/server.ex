# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule FPE.FF3_1.Setup.Server do
  @moduledoc false

  use GenServer

  ## Types

  defmodule Args do
    @moduledoc false
    defstruct [:module, :key, :radix_or_alphabet_or_codec]

    @type t :: %__MODULE__{
            module: module,
            key: FPE.FF3_1.key(),
            radix_or_alphabet_or_codec: FPE.FF3_1.radix() | FPE.FF3_1.alphabet() | FPE.FF3_1.codec()
          }
  end

  defmodule State do
    @moduledoc false
    defstruct [:args]

    @type t :: %__MODULE__{
            args: Args.t()
          }
  end

  defmodule SharedState do
    @moduledoc false
    defstruct [:ctx]

    @type t :: %__MODULE__{
            ctx: FPE.t()
          }
  end

  ## API

  def child_spec(args) do
    %{
      id: {__MODULE__, args.module},
      start: {__MODULE__, :start_link, [args]}
    }
  end

  def start_link(args) do
    GenServer.start_link(__MODULE__, [args], name: server_name(args.module))
  end

  def get_ctx(module) do
    pterm_key = shared_state_key(module)

    try do
      :persistent_term.get(pterm_key)
    catch
      :error, :badarg when is_atom(module) ->
        {:error, {:ctx_not_found_for_module, module}}
    else
      %SharedState{ctx: ctx} ->
        {:ok, ctx}
    end
  end

  def stop(pid, reason \\ :normal) do
    GenServer.stop(pid, reason)
  end

  ## GenServer

  @impl true
  def init([args]) do
    case FPE.new(args.key, :ff3_1, args.radix_or_alphabet_or_codec) do
      {:ok, ctx} ->
        # always invoke terminate/2
        _ = Process.flag(:trap_exit, true)
        shared_state = %SharedState{ctx: ctx}
        pterm_key = shared_state_key(args.module)
        :persistent_term.put(pterm_key, shared_state)
        state = %State{args: args}
        {:ok, state}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def terminate(reason, state) do
    if termination_wholesome?(reason) do
      pterm_key = shared_state_key(state.args.module)
      _ = :persistent_term.erase(pterm_key)
    end
  end

  ## Internal Functions

  defp server_name(module) do
    String.to_atom("fpe.setup.server.#{module}")
  end

  defp shared_state_key(module) do
    {__MODULE__, module}
  end

  defp termination_wholesome?(reason) do
    case reason do
      :normal -> true
      :shutdown -> true
      {:shutdown, _} -> true
      _other -> false
    end
  end
end
