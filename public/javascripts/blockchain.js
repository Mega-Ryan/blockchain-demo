/////////////////////////
// global variable setup
/////////////////////////

async function setup() {
  const initialMessage = "initial message";
  try {
    const response = await axios.get(`/api/setup/${initialMessage}`);
    console.log('setup Response:', response.data.result);
    return response.data.result;  // Axios automatically handles JSON parsing
  } catch (error) {
    console.error('setup Error:', error);
  }
}

async function chameleonhash(hashinput) {
  const hashinfo = hashinput;
  console.log('frontend hashinput:', hashinfo);
  try {
    const response = await axios.post('/api/hash', { hashinfo })
    console.log('frontend chameleonhash response:', response.data.result);
    return response.data.result;  // Axios automatically handles JSON parsing
  } catch (error) {
    console.error('chameleonhash Error:', error);
  }
}

async function adapt(adaptInput) {
  const adaptinfo = adaptInput;
  console.log('adaptInput:', adaptinfo.h);
  try {
    const response = await axios.post('/api/adapt', { adaptinfo })
    console.log('adapt Response:', response.data.result.new_h);
    return response.data.result;  // Axios automatically handles JSON parsing
  } catch (error) {
    console.error('adapt Error:', error);
  }
}

async function setupBlock(block, chain) {
  const result = await setup();
  $('#block' + block + 'chain' + chain + 'matrixA').val(JSON.stringify(result.A));
  $('#block' + block + 'chain' + chain + 'trapdoorA_e').val(JSON.stringify(result.trapdoor.e));
  $('#block' + block + 'chain' + chain + 'trapdoorA_r').val(JSON.stringify(result.trapdoor.r));
  $('#block' + block + 'chain' + chain + 'nonce_z').val(JSON.stringify(result.z));
  $('#block' + block + 'chain' + chain + 'nonce_e1').val(JSON.stringify(result.e1));
  $('#block' + block + 'chain' + chain + 'nonce_e2').val(JSON.stringify(result.e2));
  $('#block' + block + 'chain' + chain + 'data').val("initial message");
  $('#block' + block + 'chain' + chain + 'hash').val(JSON.stringify(result.h));

  if (block > 1) {
    $('#block' + block + 'chain' + chain + 'previous').val($('#block' + (block - 1).toString() + 'chain' + chain + 'hash').val());
  }
  updateState(block, chain);
}

async function updateHash(block, chain) {
  // update the hash value for this block
  const hashinput = {
    A: JSON.parse($('#block' + block + 'chain' + chain + 'matrixA').val()),
    z: JSON.parse($('#block' + block + 'chain' + chain + 'nonce_z').val()),
    e1: JSON.parse($('#block' + block + 'chain' + chain + 'nonce_e1').val()),
    e2: JSON.parse($('#block' + block + 'chain' + chain + 'nonce_e2').val()),
    message: $('#block' + block + 'chain' + chain + 'data').val()
  };
  const result = await chameleonhash(hashinput);
  // console.log('updateHash response:', result);
  $('#block' + block + 'chain' + chain + 'hash').val(JSON.stringify(result.h));
  updateState(block, chain);
}

async function adaptBlock(block, chain) {
  if ($('#block' + block + 'chain' + chain + 'newdata').val() == "") {
    console.log('No new data to adapt');
    return;
  }
  if ($('#block' + block + 'chain' + chain + 'newdata').val() == $('#block' + block + 'chain' + chain + 'data').val()) {
    console.log('New data is the same as old data');
    return;
  }
  const adaptInput = {
    A: JSON.parse($('#block' + block + 'chain' + chain + 'matrixA').val()),
    trapdoor_e: JSON.parse($('#block' + block + 'chain' + chain + 'trapdoorA_e').val()),
    trapdoor_r: JSON.parse($('#block' + block + 'chain' + chain + 'trapdoorA_r').val()),
    z: JSON.parse($('#block' + block + 'chain' + chain + 'nonce_z').val()),
    e1: JSON.parse($('#block' + block + 'chain' + chain + 'nonce_e1').val()),
    e2: JSON.parse($('#block' + block + 'chain' + chain + 'nonce_e2').val()),
    h: JSON.parse($('#block' + block + 'chain' + chain + 'hash').val()),
    message: $('#block' + block + 'chain' + chain + 'data').val(),
    new_message: $('#block' + block + 'chain' + chain + 'newdata').val()
  };
  const result = await adapt(adaptInput);
  $('#block' + block + 'chain' + chain + 'nonce_z').val(JSON.stringify(result.new_z));
  $('#block' + block + 'chain' + chain + 'nonce_e1').val(JSON.stringify(result.new_e1));
  $('#block' + block + 'chain' + chain + 'nonce_e2').val(JSON.stringify(result.new_e2));
  $('#block' + block + 'chain' + chain + 'hash').val(JSON.stringify(result.new_h));
  $('#block' + block + 'chain' + chain + 'data').val($('#block' + block + 'chain' + chain + 'newdata').val());
  updateState(block, chain);
}

function updateState(block, chain) {
  // set the well background red or green for this block
  if (block == 1) {
    $('#block' + block + 'chain' + chain + 'well').removeClass('well-error').addClass('well-success');
  }
  else if ($('#block' + block + 'chain' + chain + 'previous').val() == $('#block' + (block - 1).toString() + 'chain' + chain + 'hash').val()) {
    $('#block' + block + 'chain' + chain + 'well').removeClass('well-error').addClass('well-success');
  } else {
    $('#block' + block + 'chain' + chain + 'well').removeClass('well-success').addClass('well-error');
  }
}

function updatePrevHash(block, chain) {
  if (block > 1) {
    $('#block' + block + 'chain' + chain + 'previous').val($('#block' + (block - 1).toString() + 'chain' + chain + 'hash').val());
  }
  updateState(block, chain);
}


