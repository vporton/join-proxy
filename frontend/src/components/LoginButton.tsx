import { useInternetIdentity } from "ic-use-internet-identity";

export function LoginButton() {
  const { isLoggingIn, login, clear: clearIdentity, identity, status } = useInternetIdentity();

  function handleClick() {
    if (identity) {
      clearIdentity();  // Clear the identity
    } else {
      login();          // Open Internet Identity login
    }
  }

  const text = () => {
    if (identity) {
      return "Logout";
    } else if (isLoggingIn) {
      return "Logging in...";
    }
    return "Login";
  };

  return (
    <button onClick={handleClick} disabled={isLoggingIn}>
      {text()}
    </button>
  );
}